#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "linux/userfaultfd.h"

#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "criu-plugin.h"
#include "pagemap.h"
#include "files-reg.h"
#include "kerndat.h"
#include "mem.h"
#include "uffd.h"
#include "util-pie.h"
#include "protobuf.h"
#include "pstree.h"
#include "crtools.h"
#include "cr_options.h"
#include "xmalloc.h"
#include <compel/plugins/std/syscall-codes.h>
#include "restorer.h"
#include "page-xfer.h"
#include "common/lock.h"
#include "rst-malloc.h"
#include "fdstore.h"
#include "util.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "uffd: "

#define lp_debug(lpi, fmt, arg...) pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...) pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...) pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...) pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

#define NEED_UFFD_API_FEATURES (UFFD_FEATURE_EVENT_FORK |	    \
				UFFD_FEATURE_EVENT_REMAP |	    \
				UFFD_FEATURE_EVENT_UNMAP |	    \
				UFFD_FEATURE_EVENT_REMOVE)

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

#define LAZY_PAGES_RESTORE_FINISHED	0x52535446	/* ReSTore Finished */

static mutex_t *lazy_sock_mutex;

struct lazy_range {
	struct list_head l;
	unsigned long start;		/* run-time start address */
	unsigned long end;		/* run-time end address */
	unsigned long img_start;	/* start address at the dump time */
};

struct lazy_iov {
	struct lazy_range rng;
	bool queued;
};

struct lazy_vma {
	struct lazy_range rng;
	struct list_head iovs;
};

struct lazy_range_info {
	int off;
	int alloc_size;
	int (*drop)(struct lazy_range *rng);
	int (*split)(struct lazy_range *rng, unsigned long addr);
};

static int __drop_iov(struct lazy_range *rng);

static const struct lazy_range_info iov_range_info = {
	.off = offsetof(struct lazy_iov, rng),
	.alloc_size = sizeof(struct lazy_iov),
	.drop = __drop_iov,
	.split = NULL,
};

static int __split_vma(struct lazy_range *rng, unsigned long addr);

static const struct lazy_range_info vma_range_info = {
	.off = offsetof(struct lazy_vma, rng),
	.alloc_size = sizeof(struct lazy_vma),
	.drop = NULL,
	.split = __split_vma,
};

/*
 * Any request is a memory range where it's start address is the
 * actual #PF (or background fetch) destination and it's img_start is
 * the corresponding address at the dump time
 */
#define lp_req lazy_range

struct lazy_pages_info {
	int pid;

	struct list_head vmas;
	struct list_head reqs;

	struct lazy_pages_info *parent;
	unsigned num_children;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	void *buf;
};

/* global lazy-pages daemon state */
static LIST_HEAD(lpis);
static LIST_HEAD(exiting_lpis);
static LIST_HEAD(pending_lpis);
static int epollfd;
static bool restore_finished;
static struct epoll_rfd lazy_sk_rfd;
/* socket for communication with lazy-pages daemon */
static int lazy_pages_sk_id = -1;

static int handle_uffd_event(struct epoll_rfd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->vmas);
	INIT_LIST_HEAD(&lpi->reqs);
	INIT_LIST_HEAD(&lpi->l);
	lpi->lpfd.read_event = handle_uffd_event;

	return lpi;
}

static void free_iovs(struct lazy_vma *vma)
{
	struct lazy_iov *p, *n;

	list_for_each_entry_safe(p, n, &vma->iovs, rng.l) {
		list_del(&p->rng.l);
		xfree(p);
	}
}

static void free_vmas(struct lazy_pages_info *lpi)
{
	struct lazy_vma *p, *n;

	list_for_each_entry_safe(p, n, &lpi->vmas, rng.l) {
		free_iovs(p);
		list_del(&p->rng.l);
		xfree(p);
	}
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	if (!lpi)
		return;
	free(lpi->buf);
	free_vmas(lpi);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->parent)
		lpi->parent->num_children--;
	if (!lpi->parent && !lpi->num_children && lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	free(lpi);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	int len;

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path),
		       "%s", LAZY_PAGES_SOCK_NAME);
	if (len >= sizeof(saddr->sun_path)) {
		pr_err("Wrong UNIX socket name: %s\n", LAZY_PAGES_SOCK_NAME);
		return -1;
	}

	return 0;
}

static int send_uffd(int sendfd, int pid)
{
	int fd;
	int ret = -1;

	if (sendfd < 0)
		return -1;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("%s: get_service_fd\n", __func__);
		return -1;
	}

	mutex_lock(lazy_sock_mutex);

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	pr_debug("Sending PID %d\n", pid);
	if (send(fd, &pid, sizeof(pid), 0) < 0) {
		pr_perror("PID sending error");
		goto out;
	}

	/* for a zombie process pid will be negative */
	if (pid < 0) {
		ret = 0;
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_err("send_fd error\n");
		goto out;
	}

	ret = 0;
out:
	mutex_unlock(lazy_sock_mutex);
	close(fd);
	return ret;
}

int lazy_pages_setup_zombie(int pid)
{
	if (!opts.lazy_pages)
		return 0;

	if (send_uffd(0, -pid))
		return -1;

	return 0;
}

bool uffd_noncooperative(void)
{
	unsigned long features = NEED_UFFD_API_FEATURES;

	return (kdat.uffd_features & features) == features;
}

int uffd_open(int flags, unsigned long *features)
{
	struct uffdio_api uffdio_api = { 0 };
	int uffd;

	uffd = syscall(SYS_userfaultfd, flags);
	if (uffd == -1) {
		pr_perror("Lazy pages are not available");
		return -errno;
	}

	uffdio_api.api = UFFD_API;
	if (features)
		uffdio_api.features = *features;

	if (ioctl(uffd, UFFDIO_API, &uffdio_api)) {
		pr_perror("Failed to get uffd API");
		goto err;
	}

	if (uffdio_api.api != UFFD_API) {
		pr_err("Incompatible uffd API: expected %Lu, got %Lu\n",
		       UFFD_API, uffdio_api.api);
		goto err;
	}

	if (features)
		*features = uffdio_api.features;

	return uffd;

err:
	close(uffd);
	return -1;
}

/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(int pid, struct task_restore_args *task_args)
{
	unsigned long features = kdat.uffd_features & NEED_UFFD_API_FEATURES;

	if (!opts.lazy_pages) {
		task_args->uffd = -1;
		return 0;
	}

	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &features);
	if (task_args->uffd < 0) {
		pr_perror("Unable to open an userfaultfd descriptor");
		return -1;
	}

	if (send_uffd(task_args->uffd, pid) < 0)
		goto err;

	return 0;
err:
	close(task_args->uffd);
	return -1;
}

int prepare_lazy_pages_socket(void)
{
	int fd, len, ret = -1;
	struct sockaddr_un sun;

	if (!opts.lazy_pages)
		return 0;

	if (prepare_sock_addr(&sun))
		return -1;

	lazy_sock_mutex = shmalloc(sizeof(*lazy_sock_mutex));
	if (!lazy_sock_mutex)
		return -1;

	mutex_init(lazy_sock_mutex);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (connect(fd, (struct sockaddr *) &sun, len) < 0) {
		pr_perror("connect to %s failed", sun.sun_path);
		goto out;
	}

	lazy_pages_sk_id = fdstore_add(fd);
	if (lazy_pages_sk_id < 0) {
		pr_perror("Can't add fd to fdstore");
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(saddr->sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(saddr->sun_path);

	if (bind(fd, (struct sockaddr *) saddr, len) < 0) {
		goto out;
	}

	if (listen(fd, 10) < 0) {
		goto out;
	}

	return fd;

out:
	close(fd);
	return -1;
}

static MmEntry *init_mm_entry(struct lazy_pages_info *lpi)
{
	struct cr_img *img;
	MmEntry *mm;
	int ret;

	img = open_image(CR_FD_MM, O_RSTR, lpi->pid);
	if (!img)
		return NULL;

	ret = pb_read_one_eof(img, &mm, PB_MM);
	close_image(img);
	if (ret == -1)
		return NULL;
	lp_debug(lpi, "Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static struct lazy_iov *find_iov_in_vma(struct lazy_vma *vma,
					unsigned long addr)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &vma->iovs, rng.l)
		if (addr >= iov->rng.start && addr < iov->rng.end)
			return iov;

	return NULL;
}

static struct lazy_vma *find_vma(struct lazy_pages_info *lpi,
				 unsigned long addr)
{
	struct lazy_vma *vma;

	list_for_each_entry(vma, &lpi->vmas, rng.l)
		if (addr >= vma->rng.start && addr < vma->rng.end)
			return vma;

	return NULL;
}

static struct lazy_iov *find_iov(struct lazy_pages_info *lpi,
				 unsigned long addr)
{
	struct lazy_vma *vma;

	vma = find_vma(lpi, addr);
	if (!vma)
		return NULL;

	return find_iov_in_vma(vma, addr);
}

static int split_range(struct lazy_range *rng, unsigned long addr,
		       const struct lazy_range_info *lri)
{
	void *_new;
	struct lazy_range *new;

	_new = xzalloc(lri->alloc_size);
	if (!_new)
		return -1;
	new = _new + lri->off;

	new->start = addr;
	new->img_start = rng->img_start + addr - rng->start;
	new->end = rng->end;
	rng->end = addr;
	list_add(&new->l, &rng->l);

	if (lri->split)
		return lri->split(rng, addr);

	return 0;
}

static int split_iov(struct lazy_iov *iov, unsigned long addr)
{
	return split_range(&iov->rng, addr, &iov_range_info);
}

static int __split_vma(struct lazy_range *rng, unsigned long addr)
{
	struct lazy_vma *new, *vma;
	struct lazy_iov *iov, *n;

	vma = container_of(rng, struct lazy_vma, rng);
	new = list_entry(vma->rng.l.next, struct lazy_vma, rng.l);
	INIT_LIST_HEAD(&new->iovs);

	list_for_each_entry_safe(iov, n, &vma->iovs, rng.l) {
		if (addr > iov->rng.start && addr < iov->rng.end) {
			if (split_iov(iov, addr))
				return -1;
			list_safe_reset_next(iov, n, rng.l);
		}

		if (iov->rng.start >= addr)
			list_move(&iov->rng.l, &new->iovs);
	}

	return 0;
}

static int split_vma(struct lazy_vma *vma, unsigned long addr)
{
	return split_range(&vma->rng, addr, &vma_range_info);
}

static int copy_iovs(struct lazy_vma *src, struct lazy_vma *dst,
		     int *max_iov_len)
{
	struct lazy_iov *iov, *new;

	list_for_each_entry(iov, &src->iovs, rng.l) {
		new = xzalloc(sizeof(*new));
		if (!new)
			goto free_iovs;

		new->rng.start = iov->rng.start;
		new->rng.img_start = iov->rng.img_start;
		new->rng.end = iov->rng.end;

		list_add_tail(&new->rng.l, &dst->iovs);

		if (new->rng.end - new->rng.start > *max_iov_len)
			*max_iov_len = new->rng.end - new->rng.start;
	}

	return 0;

free_iovs:
	free_iovs(dst);
	return -1;
}

static int copy_vmas(struct lazy_pages_info *src, struct lazy_pages_info *dst)
{
	struct lazy_vma *vma, *new;
	int max_iov_len = 0;

	list_for_each_entry(vma, &src->vmas, rng.l) {
		new = xzalloc(sizeof(*new));
		if (!new)
			goto free_vmas;

		new->rng.start = vma->rng.start;
		new->rng.img_start = vma->rng.img_start;
		new->rng.end = vma->rng.end;

		INIT_LIST_HEAD(&new->iovs);
		INIT_LIST_HEAD(&new->rng.l);

		list_add_tail(&new->rng.l, &dst->vmas);

		copy_iovs(vma, new, &max_iov_len);
	}

	if (posix_memalign(&dst->buf, PAGE_SIZE, max_iov_len))
		goto free_vmas;

	return 0;

free_vmas:
	free_vmas(dst);
	return -1;
}

static int drop_ranges(struct list_head *list, unsigned long addr, int len,
		       const struct lazy_range_info *lri)
{
	struct lazy_range *rng, *n;

	list_for_each_entry_safe(rng, n, list, l) {
		unsigned long start = rng->start;
		unsigned long end = rng->end;

		if (len <= 0 || addr + len < start)
			break;

		if (addr >= end)
			continue;

		if (addr < start) {
			len -= (start - addr);
			addr = start;
		}

		if (lri->drop)
			if (lri->drop(rng))
				return -1;

		/*
		 * The range completely fits into the current RNG.
		 * If addr equals rng->start we just "drop" the
		 * beginning of the RNG. Otherwise, we make the RNG to
		 * end at addr, and add a new RNG that starts at
		 * addr + len.
		 */
		if (addr + len < end) {
			if (addr == start) {
				rng->start += len;
				rng->img_start += len;
			} else {
				if (split_range(rng, addr + len, lri))
					return -1;
				rng->end = addr;
			}
			break;
		}

		/*
		 * The range spawns beyond the end of the current RNG.
		 * If addr equals rng->start we just "drop" the entire
		 * RNG.  Otherwise, we cut the beginning of the RNG
		 * and continue to the next one with the updated range
		 */
		if (addr == start) {
			void *p = rng - lri->off;
			list_del(&rng->l);
			xfree(p);
		} else {
			rng->end = addr;
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

static int __drop_iov(struct lazy_range *rng)
{
	struct lazy_iov *iov;

	iov = container_of(rng, struct lazy_iov, rng);
	iov->queued = false;

	return 0;
}

/*
 * Purge range (addr, addr + len) from lazy_iovs. The range may
 * cover several continuous IOVs.
 */
static int drop_iovs_in_vma(struct lazy_vma *vma, unsigned long addr, int len)
{
	return drop_ranges(&vma->iovs, addr, len, &iov_range_info);
}

static int drop_iovs(struct lazy_pages_info *lpi, unsigned long addr, int len)
{
	struct lazy_vma *vma;

	list_for_each_entry(vma, &lpi->vmas, rng.l) {
		if (drop_iovs_in_vma(vma, addr, len))
			return -1;
	}

	return 0;
}

static int drop_vmas(struct lazy_pages_info *lpi, unsigned long addr, int len)
{
	if (drop_iovs(lpi, addr, len))
		return -1;

	return drop_ranges(&lpi->vmas, addr, len, &vma_range_info);
}

static int unreg_vma(struct lazy_pages_info *lpi, struct lazy_vma *vma)
{
	struct uffdio_range unreg;
	int ret;

	unreg.start = vma->rng.start;
	unreg.len = vma->rng.end - vma->rng.start;

	ret = ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg);
	if (ret && errno != ENOMEM) {
		lp_perror(lpi, "Failed to unregister (%lx - %lx)",
			  vma->rng.start, vma->rng.end);

		/*
		 * For kernels that don't have non-cooperative
		 * userfaultfd events ioctl can fail because the
		 * process VM layout has changed or the process has
		 * exited and we have no way to detect it.
		 */
		if (kdat.uffd_features & NEED_UFFD_API_FEATURES)
			return -1;
	}

	return 0;
}

static int unreg_vmas(struct lazy_pages_info *lpi)
{
	struct lazy_vma *vma, *n;

	list_for_each_entry_safe(vma, n, &lpi->vmas, rng.l) {
		if (unreg_vma(lpi, vma))
			return -1;

		list_del(&vma->rng.l);
	}

	return 0;
}

static int remap_iovs_in_vma(struct lazy_vma *vma, unsigned long off)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &vma->iovs, rng.l) {
		iov->rng.start += off;
		iov->rng.end += off;
	}

	return 0;
}

static int remap_vmas(struct lazy_pages_info *lpi, unsigned long from,
		      unsigned long to, unsigned long len)
{
	unsigned long off = to - from;
	struct lazy_vma *vma, *n, *p;
	LIST_HEAD(remaps);

	list_for_each_entry_safe(vma, n, &lpi->vmas, rng.l) {
		if (from >= vma->rng.end)
			continue;

		if (len <= 0 || from + len < vma->rng.start)
			break;

		if (from < vma->rng.start) {
			len -= (vma->rng.start - from);
			from = vma->rng.start;
		}

		if (from > vma->rng.start) {
			if (split_vma(vma, from))
				return -1;
			list_safe_reset_next(vma, n, rng.l);
			continue;
		}

		if (from + len < vma->rng.end) {
			if (split_vma(vma, from + len))
				return -1;
			list_safe_reset_next(vma, n, rng.l);
		}

		/* here we have vma->start = from, vma->end <= from + len */
		if (remap_iovs_in_vma(vma, off))
			return -1;
		from = vma->rng.end;
		len -= vma->rng.end - vma->rng.start;
		vma->rng.start += off;
		vma->rng.end += off;
		list_move_tail(&vma->rng.l, &remaps);
	}

	list_for_each_entry_safe(vma, n, &remaps, rng.l) {
		list_for_each_entry(p, &lpi->vmas, rng.l) {
			if (vma->rng.start < p->rng.start) {
				list_move_tail(&vma->rng.l, &p->rng.l);
				break;
			}
			if (list_is_last(&p->rng.l, &lpi->vmas) &&
			    vma->rng.start > p->rng.start) {
				list_move(&vma->rng.l, &p->rng.l);
				break;
			}
		}
	}

	return 0;
}

static int collect_vmas(struct lazy_pages_info *lpi)
{
	struct lazy_vma *vma;
	MmEntry *mm;
	int n_vma, ret = -1;

	mm = init_mm_entry(lpi);
	if (!mm)
		return -1;

	for (n_vma = 0; n_vma < mm->n_vmas; n_vma++) {
		VmaEntry *vmae = mm->vmas[n_vma];

		if (!vma_entry_can_be_lazy(vmae))
			continue;

		vma = xzalloc(sizeof(*vma));
		if (!vma)
			goto free_vma;

		vma->rng.start = vma->rng.img_start = vmae->start;
		vma->rng.end = vmae->end;
		INIT_LIST_HEAD(&vma->iovs);
		list_add_tail(&vma->rng.l, &lpi->vmas);
	}

	ret = 0;
	goto free_mm;

free_vma:
	free_vmas(lpi);
free_mm:
	mm_entry__free_unpacked(mm, NULL);
	return ret;
}

/*
 * Create a list of IOVs that can be handled using userfaultfd. The
 * IOVs generally correspond to lazy pagemap entries, except the cases
 * when a single pagemap entry covers several VMAs. In those cases
 * IOVs are split at VMA boundaries because UFFDIO_COPY may be done
 * only inside a single VMA.
 * We assume here that pagemaps and VMAs are sorted.
 */
static int collect_iovs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iov *iov;
	struct lazy_vma *vma;
	int nr_pages = 0, max_iov_len = 0;
	int ret = -1;
	unsigned long start, end, len;

	if (collect_vmas(lpi))
 		return -1;

	if (unlikely(list_empty(&lpi->vmas))) {
		lp_warn(lpi, "no lazy VMAs\n");
		return 0;
	}

	vma = list_first_entry(&lpi->vmas, struct lazy_vma, rng.l);
	while (pr->advance(pr)) {
		if (!pagemap_lazy(pr->pe))
			continue;

		start = pr->pe->vaddr;
		end = start + pr->pe->nr_pages * page_size();
		nr_pages += pr->pe->nr_pages;

		list_for_each_entry_from(vma, &lpi->vmas, rng.l) {
			if (start >= vma->rng.end)
				continue;

			iov = xzalloc(sizeof(*iov));
			if (!iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->rng.end) - start;
			iov->rng.start = start;
			iov->rng.img_start = start;
			iov->rng.end = iov->rng.start + len;
			list_add_tail(&iov->rng.l, &vma->iovs);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->rng.end)
				break;

			start = vma->rng.end;
		}
	}

	if (posix_memalign(&lpi->buf, PAGE_SIZE, max_iov_len))
		goto free_iovs;

	return nr_pages;

free_iovs:
	free_vmas(lpi);
	return ret;
}

static bool has_iovs(struct lazy_pages_info *lpi)
{
	struct lazy_vma *vma;

	list_for_each_entry(vma, &lpi->vmas, rng.l)
		if (!list_empty(&vma->iovs))
			return true;

	return false;
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, int nr);

static int ud_open(int client, struct lazy_pages_info **_lpi)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int pr_flags = PR_TASK;

	lpi = lpi_init();
	if (!lpi)
		goto out;

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &lpi->pid, sizeof(lpi->pid), 0);
	if (ret != sizeof(lpi->pid)) {
		if (ret < 0)
			pr_perror("PID recv error");
		else
			pr_err("PID recv: short read\n");
		goto out;
	}

	if (lpi->pid < 0) {
		pr_debug("Zombie PID: %d\n", lpi->pid);
		lpi_fini(lpi);
		return 0;
	}

	lpi->lpfd.fd = recv_fd(client);
	if (lpi->lpfd.fd < 0) {
		pr_err("recv_fd error\n");
		goto out;
	}
	pr_debug("Received PID: %d, uffd: %d\n", lpi->pid, lpi->lpfd.fd);

	if (opts.use_page_server)
		pr_flags |= PR_REMOTE;
	ret = open_page_read(lpi->pid, &lpi->pr, pr_flags);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	lpi->pr.io_complete = uffd_io_complete;

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	ret = collect_iovs(lpi);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	lp_debug(lpi, "Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	list_add_tail(&lpi->l, &lpis);
	*_lpi = lpi;

	return 0;

out:
	lpi_fini(lpi);
	return -1;
}

static int handle_exit(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "EXIT\n");
	if (epoll_del_rfd(epollfd, &lpi->lpfd))
		return -1;
	free_vmas(lpi);
	close(lpi->lpfd.fd);
	lpi->lpfd.fd = 0;

	/* keep it for tracking in-flight requests and for the summary */
	list_move_tail(&lpi->l, &lpis);

	return 0;
}

static int uffd_check_op_error(struct lazy_pages_info *lpi, const char *op,
			       unsigned long len, unsigned long rc_len, int rc)
{
	if (rc) {
		if (errno == ENOSPC || errno == ESRCH) {
			handle_exit(lpi);
			return 0;
		}
		if (rc_len != -EEXIST) {
			lp_perror(lpi, "%s: rc:%d copy:%ld, errno:%d",
				 op, rc, rc_len, errno);
			return -1;
		}
	} else if (rc_len != len) {
		lp_err(lpi, "%s unexpected size %ld\n", op, rc_len);
		return -1;
	}

	return 0;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = nr_pages * page_size();
	int rc;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy);
	if (uffd_check_op_error(lpi, "copy", len, uffdio_copy.copy, rc))
		return -1;

	lpi->copied_pages += nr_pages;

	return 0;
}

static int uffd_io_complete(struct page_read *pr, unsigned long img_addr, int nr)
{
	struct lazy_pages_info *lpi;
	unsigned long addr = 0;
	struct lp_req *req;

	lpi = container_of(pr, struct lazy_pages_info, pr);

	list_for_each_entry(req, &lpi->reqs, l) {
		if (req->img_start == img_addr) {
			addr = req->start;
			list_del(&req->l);
			xfree(req);
			break;
		}
	}

	/*
	 * The process may exit while we still have requests in
	 * flight. We just drop the request and the received data in
	 * this case to avoid making uffd unhappy
	 */
	if (list_empty(&lpi->vmas))
	    return 0;

	BUG_ON(!addr);

	if (uffd_copy(lpi, addr, nr))
		return -1;

	return drop_iovs(lpi, addr, nr * PAGE_SIZE);
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;
	int rc;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	lp_debug(lpi, "zero page at 0x%llx\n", address);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	if (uffd_check_op_error(lpi, "zero", len, uffdio_zeropage.zeropage, rc))
		return -1;

	return 0;
}

/*
 * Seek for the requested address in the pagemap. If it is found, the
 * subsequent call to pr->page_read will bring us the data. If the
 * address is not found in the pagemap, but no error occurred, the
 * address should be mapped to zero pfn.
 *
 * Returns 0 for zero pages, 1 for "real" pages and negative value on
 * error
 */
static int uffd_seek_pages(struct lazy_pages_info *lpi, __u64 address, int nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret) {
		lp_err(lpi, "no pagemap covers %llx\n", address);
		return -1;
	}

	return 0;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr, unsigned flags)
{
	int ret;

	ret = uffd_seek_pages(lpi, address, nr);
	if (ret)
		return ret;

	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		lp_err(lpi, "failed reading pages at %llx\n", address);
		return ret;
	}

	return 0;
}

static struct lazy_iov *first_pending_iov(struct lazy_pages_info *lpi)
{
	struct lazy_vma *vma;
	struct lazy_iov *iov;

	list_for_each_entry(vma, &lpi->vmas, rng.l) {
		list_for_each_entry(iov, &vma->iovs, rng.l)
			if (!iov->queued)
				return iov;
	}

	return NULL;
}

static bool is_iov_queued(struct lazy_pages_info *lpi, struct lazy_iov *iov)
{
	struct lp_req *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (req->start >= iov->rng.start && req->start < iov->rng.end)
			return true;

	return false;
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;
	struct lp_req *req;
	int nr_pages, err;

	iov = first_pending_iov(lpi);
	if (!iov)
		return 0;

	if (is_iov_queued(lpi, iov))
		return 0;

	req = xzalloc(sizeof(*req));
	if (!req)
		return -1;

	req->start = iov->rng.start;
	req->img_start = iov->rng.img_start;
	req->end = iov->rng.end;
	list_add(&req->l, &lpi->reqs);
	iov->queued = true;

	nr_pages = (req->end - req->start) / PAGE_SIZE;

	err = uffd_handle_pages(lpi, req->img_start, nr_pages,
				PR_ASYNC | PR_ASAP);
	if (err < 0) {
		lp_err(lpi, "Error during UFFD copy\n");
		return -1;
	}

	return 0;
}

static int handle_remove(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct uffdio_range unreg;

	unreg.start = msg->arg.remove.start;
	unreg.len = msg->arg.remove.end - msg->arg.remove.start;

	lp_debug(lpi, "%s: %Lx(%Lx)\n",
		 msg->event == UFFD_EVENT_REMOVE ? "REMOVE" : "UNMAP",
		 unreg.start, unreg.len);

	/*
	 * The REMOVE event does not change the VMA, so we need to
	 * make sure that we won't handle #PFs in the removed
	 * range. With UNMAP, there's no VMA to worry about
	 */
	if (msg->event == UFFD_EVENT_REMOVE &&
	    ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
		/*
		 * The kernel returns -ENOMEM when unregister is
		 * called after the process has gone
		 */
		if (errno == ENOMEM) {
			handle_exit(lpi);
			return 0;
		}

		pr_perror("Failed to unregister (%llx - %llx)", unreg.start,
			  unreg.start + unreg.len);
		return -1;
	}

	return drop_vmas(lpi, unreg.start, unreg.len);
}

static int handle_remap(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	unsigned long from = msg->arg.remap.from;
	unsigned long to = msg->arg.remap.to;
	unsigned long len = msg->arg.remap.len;

	lp_debug(lpi, "REMAP: %lx -> %lx (%ld)\n", from , to, len);

	return remap_vmas(lpi, from, to, len);
}

static int handle_fork(struct lazy_pages_info *parent_lpi, struct uffd_msg *msg)
{
	struct lazy_pages_info *lpi;
	int uffd = msg->arg.fork.ufd;

	lp_debug(parent_lpi, "FORK: child with ufd=%d\n", uffd);

	lpi = lpi_init();
	if (!lpi)
		return -1;

	if (copy_vmas(parent_lpi, lpi))
		goto out;

	lpi->pid = parent_lpi->pid;
	lpi->lpfd.fd = uffd;
	lpi->parent = parent_lpi->parent ? parent_lpi->parent : parent_lpi;
	lpi->copied_pages = lpi->parent->copied_pages;
	lpi->total_pages = lpi->parent->total_pages;
	list_add_tail(&lpi->l, &pending_lpis);

	dup_page_read(&lpi->parent->pr, &lpi->pr);

	lpi->parent->num_children++;

	return 1;

out:
	lpi_fini(lpi);
	return -1;
}

static int complete_forks(int epollfd, struct epoll_event **events, int *nr_fds)
{
	struct lazy_pages_info *lpi, *n;

	list_for_each_entry(lpi, &pending_lpis, l)
		(*nr_fds)++;

	*events = xrealloc(*events, sizeof(struct epoll_event) * (*nr_fds));
	if (!*events)
		return -1;

	list_for_each_entry_safe(lpi, n, &pending_lpis, l) {
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			return -1;

		list_del_init(&lpi->l);
		list_add_tail(&lpi->l, &lpis);
	}

	return 0;
}

static bool is_page_queued(struct lazy_pages_info *lpi, unsigned long addr)
{
	struct lp_req *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (addr >= req->start && addr < req->end)
			return true;

	return false;
}

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lp_req *req;
	struct lazy_iov *iov;
	__u64 address;
	int ret;

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_debug(lpi, "#PF at 0x%llx\n", address);

	if (is_page_queued(lpi, address))
		return 0;

	if (list_empty(&lpi->vmas))
		return 0;

	iov = find_iov(lpi, address);
	if (!iov)
		return uffd_zero(lpi, address, 1);

	req = xzalloc(sizeof(*req));
	if (!req)
		return -1;
	req->start = address;
	req->img_start = iov->rng.img_start + (address - iov->rng.start);
	req->end = req->start + PAGE_SIZE;
	list_add(&req->l, &lpi->reqs);

	ret = uffd_handle_pages(lpi, req->img_start, 1, PR_ASYNC | PR_ASAP);
	if (ret < 0) {
		lp_err(lpi, "Error during regular page copy\n");
		return -1;
	}

	return 0;
}

static int handle_uffd_event(struct epoll_rfd *lpfd)
{
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	int ret;

	lpi = container_of(lpfd, struct lazy_pages_info, lpfd);

	ret = read(lpfd->fd, &msg, sizeof(msg));
	if (!ret)
		return 1;

	if (ret != sizeof(msg)) {
		/* we've already handled the page fault for another thread */
		if (errno == EAGAIN)
			return 0;
		if (ret < 0)
			lp_perror(lpi, "Can't read uffd message");
		else
			lp_err(lpi, "Can't read uffd message: short read");
		return -1;
	}

	switch (msg.event) {
	case UFFD_EVENT_PAGEFAULT:
		return handle_page_fault(lpi, &msg);
	case UFFD_EVENT_REMOVE:
	case UFFD_EVENT_UNMAP:
		return handle_remove(lpi, &msg);
	case UFFD_EVENT_REMAP:
		return handle_remap(lpi, &msg);
	case UFFD_EVENT_FORK:
		return handle_fork(lpi, &msg);
	default:
		lp_err(lpi, "unexpected uffd event %u\n", msg.event);
		return -1;
	}

	return 0;
}

static void lazy_pages_summary(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "UFFD transferred pages: (%ld/%ld)\n",
		 lpi->copied_pages, lpi->total_pages);

#if 0
	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		lp_warn(lpi, "Only %ld of %ld pages transferred via UFFD\n"
			"Something probably went wrong.\n",
			lpi->copied_pages, lpi->total_pages);
		return 1;
	}
#endif
}

#define POLL_TIMEOUT 1000

static int handle_requests(int epollfd, struct epoll_event *events, int nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	/* FIXME -- timeout should decrease over time...  */
	int poll_timeout = POLL_TIMEOUT;
	int ret;

	for (;;) {
		ret = epoll_run_rfds(epollfd, events, nr_fds, poll_timeout);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			if (complete_forks(epollfd, &events, &nr_fds))
				return -1;
			continue;
		}

		/* don't start backround fetch before restore is finished */
		if (!restore_finished)
			continue;

		if (poll_timeout)
			pr_debug("Start handling remaining pages\n");

		poll_timeout = 0;

		if (list_empty(&lpis))
			break;

		list_for_each_entry_safe(lpi, n, &lpis, l) {
			if (list_empty(&lpi->vmas) && list_empty(&lpi->reqs)) {
				lazy_pages_summary(lpi);
				list_del(&lpi->l);
				lpi_fini(lpi);
				continue;
			}

			if (!has_iovs(lpi) && list_empty(&lpi->reqs))
				if (unreg_vmas(lpi))
					goto out;

			ret = handle_remaining_pages(lpi);
			if (ret < 0)
				goto out;
			break;
		}
	}

out:
	return ret;

}

int lazy_pages_finish_restore(void)
{
	uint32_t fin = LAZY_PAGES_RESTORE_FINISHED;
	int fd, ret;

	if (!opts.lazy_pages)
		return 0;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("No lazy-pages socket\n");
		return -1;
	}

	ret = send(fd, &fin, sizeof(fin), 0);
	if (ret != sizeof(fin))
		pr_perror("Failed sending restore finished indication");

	close(fd);

	return ret < 0 ? ret : 0;
}

static int prepare_lazy_socket(void)
{
	int listen;
	struct sockaddr_un saddr;

	if (prepare_sock_addr(&saddr))
		return -1;

	pr_debug("Waiting for incoming connections on %s\n", saddr.sun_path);
	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	return listen;
}

static int lazy_sk_read_event(struct epoll_rfd *rfd)
{
	uint32_t fin;
	int ret;

	ret = recv(rfd->fd, &fin, sizeof(fin), 0);
	/*
	 * epoll sets POLLIN | POLLHUP for the EOF case, so we get short
	 * read just befor hangup_event
	 */
	if (!ret)
		return 0;

	if (ret != sizeof(fin)) {
		pr_perror("Failed getting restore finished indication");
		return -1;
	}

	if (fin != LAZY_PAGES_RESTORE_FINISHED) {
		pr_err("Unexpected response: %x\n", fin);
		return -1;
	}

	restore_finished = true;

	return 0;
}

static int lazy_sk_hangup_event(struct epoll_rfd *rfd)
{
	if (!restore_finished) {
		pr_err("Restorer unexpectedly closed the connection\n");
		return -1;
	}

	return 0;
}

static int prepare_uffds(int listen, int epollfd)
{
	int i;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *) &saddr, &len)) < 0) {
		pr_perror("server_accept error");
		close(listen);
		return -1;
	}

	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi = NULL;
		if (ud_open(client, &lpi))
			goto close_uffd;
		if (lpi == NULL)
			continue;
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			goto close_uffd;
	}

	lazy_sk_rfd.fd = client;
	lazy_sk_rfd.read_event = lazy_sk_read_event;
	lazy_sk_rfd.hangup_event = lazy_sk_hangup_event;
	if (epoll_add_rfd(epollfd, &lazy_sk_rfd))
		goto close_uffd;

	close(listen);
	return 0;

close_uffd:
	close_safe(&client);
	close(listen);
	return -1;
}

int cr_lazy_pages(bool daemon)
{
	struct epoll_event *events;
	int nr_fds;
	int lazy_sk;
	int ret;

	if (kerndat_uffd() || !kdat.has_uffd)
		return -1;

	if (prepare_dummy_pstree())
		return -1;

	lazy_sk = prepare_lazy_socket();
	if (lazy_sk < 0)
		return -1;

	if (daemon) {
		ret = cr_daemon(1, 0, &lazy_sk, -1);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			return -1;
		}
		if (ret > 0) { /* parent task, daemon started */
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					return -1;
				}
			}

			return 0;
		}
	}

	if (close_status_fd())
		return -1;

	/*
	 * we poll nr_tasks userfault fds, UNIX socket between lazy-pages
	 * daemon and the cr-restore, and, optionally TCP socket for
	 * remote pages
	 */
	nr_fds = task_entries->nr_tasks + (opts.use_page_server ? 2 : 1);
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(lazy_sk, epollfd))
		return -1;

	if (opts.use_page_server) {
		if (connect_to_page_server_to_recv(epollfd))
			return -1;
	}

	ret = handle_requests(epollfd, events, nr_fds);

	return ret;
}
