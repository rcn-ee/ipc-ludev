/*
 * cmemk.c
 */
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#include <linux/version.h>

#include <linux/cmemk_stub.h>

#include <ti/cmem.h>


/*
 * Poor man's config params
 */

#ifdef __DEBUG
#define __D(fmt, args...) printk(KERN_DEBUG "CMEMK Debug: " fmt, ## args)
#else
#define __D(fmt, args...)
#endif

#define __E(fmt, args...) printk(KERN_ERR "CMEMK Error: " fmt, ## args)

#define MAXTYPE(T) ((T) (((T)1 << ((sizeof(T) * 8) - 1) ^ ((T) -1))))

#ifndef VM_RESERVED
#define VM_RESERVED 0x00080000
#endif

static int heap_pool = 0;

static int cmem_major;
static struct proc_dir_entry *cmem_proc_entry;
static atomic_t reference_count = ATOMIC_INIT(0);
static unsigned int version = CMEM_VERSION;

static struct class *cmem_class;
static struct mutex cmem_mutex;

/* Register the module parameters. */

static int useHeapIfPoolUnavailable = 0;
MODULE_PARM_DESC(useHeapIfPoolUnavailable,
    "\n\t\t Set to 1 if you want a pool-based allocation request to"
    "\n\t\t fall back to a heap-based allocation attempt");
module_param(useHeapIfPoolUnavailable, int, S_IRUGO);

/* Describes a pool buffer */
typedef struct pool_buffer {
    struct list_head element;
    struct list_head users;
    struct page *start_page;
    unsigned long physp;
    size_t size;		/* used only for heap-based allocs */
    int count;
    int flags;			/* CMEM_CACHED or CMEM_NONCACHED */
} pool_buffer;

typedef struct registered_user {
    struct list_head element;
    struct file *filp;
} registered_user;

/* Forward declaration of system calls */
static long ioctl(struct file *filp, unsigned int cmd, unsigned long args);
static int mmap(struct file *filp, struct vm_area_struct *vma);
static int open(struct inode *inode, struct file *filp);
static int release(struct inode *inode, struct file *filp);

static struct file_operations cmem_fxns = {
    owner:   THIS_MODULE,
    unlocked_ioctl: ioctl,
    mmap:    mmap,
    open:    open,
    release: release
};


/* Traverses the page tables and translates a virtual adress to a physical. */
static unsigned long get_phys(unsigned long virtp)
{
    unsigned long physp = ~(0L);
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;

    /* For kernel direct-mapped memory, take the easy way */
    if (virtp >= PAGE_OFFSET) {
        physp = virt_to_phys((void *)virtp);
	__D("get_phys: virt_to_phys translated direct-mapped %#lx to %#lx\n",
	    virtp, physp);
    }

    /* this will catch, kernel-allocated, mmaped-to-usermode addresses */
    else if ((vma = find_vma(mm, virtp)) &&
             (vma->vm_flags & VM_IO) &&
             (vma->vm_pgoff)) {
        physp =  (vma->vm_pgoff << PAGE_SHIFT) + (virtp - vma->vm_start);
	__D("get_phys: find_vma translated user %#lx to %#lx\n", virtp, physp);
    }

    /* otherwise, use get_user_pages() for general userland pages */
    else {
        int res, nr_pages = 1;
        struct page *pages;

        down_read(&current->mm->mmap_sem);

        res = get_user_pages(current, current->mm,
                             virtp, nr_pages,
                             1, 0,
                             &pages, NULL);
        up_read(&current->mm->mmap_sem);

        if (res == nr_pages) {
            physp = __pa(page_address(&pages[0]) + (virtp & ~PAGE_MASK));
	    __D("get_phys: get_user_pages translated user %#lx to %#lx\n",
	        virtp, physp);
        } else {
            __E("%s: Unable to find phys addr for 0x%08lx\n",
                __FUNCTION__, virtp);
            __E("%s: get_user_pages() failed: %d\n", __FUNCTION__, res);
        }
    }

    return physp;
}

#ifdef __DEBUG
/* Only for debug */
static void dump_lists(int idx)
{
    struct list_head *busylistp = &cmem_p_objs[idx].busylist;
    struct list_head *e;
    struct pool_buffer *entry;

    if (mutex_lock_interruptible(&cmem_mutex)) {
        return;
    }

    __D("Busylist for pool %d:\n", idx);
    for (e = busylistp->next; e != busylistp; e = e->next) {

        entry = list_entry(e, struct pool_buffer, element);

        __D("Busy: Buffer with physical address %#lx\n", entry->physp);
    }

    mutex_unlock(&cmem_mutex);
}
#endif

/*
 *  ======== find_busy_entry ========
 *  find_busy_entry looks for an allocated pool buffer with
 *  phyisical addr physp.
 *
 *  Should be called with the cmem_mutex held.
 */
static struct pool_buffer *find_busy_entry(unsigned long physp, int *poolp, struct list_head **ep)
{
    struct list_head *busylistp;
    struct list_head *e;
    struct pool_buffer *entry;
    int i;

    for (i = 0; i < cmem_npools; i++) {
	busylistp = &cmem_p_objs[i].busylist;

	for (e = busylistp->next; e != busylistp; e = e->next) {
	    entry = list_entry(e, struct pool_buffer, element);
	    if (entry->physp == physp) {
		if (poolp) {
		    *poolp = i;
		}
		if (ep) {
		    *ep = e;
		}

		return entry;
	    }
	}
    }

    return NULL;
}

static int set_noncached(struct vm_area_struct *vma)
{
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    vma->vm_flags |= VM_RESERVED | VM_IO;

    if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
                        vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        __E("set_noncached: failed remap_pfn_range\n");
        return -EAGAIN;
    }

    return 0;
}

static int set_cached(struct vm_area_struct *vma)
{
    vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
                                 (L_PTE_MT_WRITETHROUGH | L_PTE_MT_BUFFERABLE)
                                );
    vma->vm_flags |= VM_RESERVED | VM_IO;

    if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
                        vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        __E("set_cached: failed remap_pfn_range\n");
        return -EAGAIN;
    }

    return 0;
}

struct block_struct {
    unsigned long addr;
    size_t size;
};

static long ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
    unsigned int __user *argp = (unsigned int __user *) args;
    struct page *page;
    struct list_head *busylistp = NULL;
    struct list_head *registeredlistp;
    struct list_head *e = NULL;
    struct list_head *u;
    struct list_head *unext;
    struct pool_buffer *entry;
    struct registered_user *user;
    unsigned long physp;
    unsigned long virtp, virtp_end;
    size_t reqsize, align;
    size_t size = 0;
    int delta = MAXTYPE(int);
    int count;
    int order;
    int pool = -1;
    int i;
    struct block_struct block;
    union CMEM_AllocUnion allocDesc;

    if (_IOC_TYPE(cmd) != _IOC_TYPE(CMEM_IOCMAGIC)) {
	__E("ioctl(): bad command type 0x%x (should be 0x%x)\n",
	    _IOC_TYPE(cmd), _IOC_TYPE(CMEM_IOCMAGIC));
    }

    switch (cmd & CMEM_IOCCMDMASK) {
        /*
         * argp contains a pointer to an alloc descriptor coming in, and the
         * physical address and size of the allocated buffer when returning.
         */
        case CMEM_IOCALLOC:
	    if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
                return -EFAULT;
            }

	    pool = allocDesc.alloc_pool_inparams.poolid;

            __D("ALLOC%s ioctl received on pool %d\n",
	        cmd & CMEM_CACHED ? "CACHED" : "", pool);

            if (pool >= cmem_npools || pool < 0) {
                __E("ALLOC%s: invalid pool (%d) passed.\n",
		    cmd & CMEM_CACHED ? "CACHED" : "", pool);
                return -EINVAL;
            }

	    size = cmem_p_objs[pool].size;
	    align = 0;

	    goto alloc;

        case CMEM_IOCALLOCHEAP:
	    if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
		return -EFAULT;
	    }

	    size = allocDesc.alloc_heap_inparams.size;
	    align = allocDesc.alloc_heap_inparams.align;

            __D("ALLOCHEAP%s ioctl received on heap pool\n",
	        cmd & CMEM_CACHED ? "CACHED" : "");
	    __D("  size=%d align=%d\n", size, align);

	    if (cmem_heapsize == 0) {
		__E("ioctl: no heap available\n");
		return -EINVAL;
	    }

	    pool = 0;
alloc:
	    /* round up to next page size */
	    count = ((size - 1) >> PAGE_SHIFT) + 1;

	    order = 0;
	    align = align >> PAGE_SHIFT;
	    while (align) {
		align = align >> 1;
		order++;
	    }

	    entry = kmalloc(sizeof(struct pool_buffer), GFP_KERNEL);
	    if (!entry) {
		__E("ioctl: failed to kmalloc pool_buffer struct for heap");

		return -ENOMEM;
	    }

	    if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
	    }

	    __D("ioctl: cmem_alloc(&cmem_dev[%d], %d, %d)...\n",
	        pool, count, order);

	    page = cmem_alloc(&cmem_dev[pool], count, order);
	    if (page == NULL) {
		__E("ioctl: failed to alloc contiguous buffer of size %#x\n",
		    size);

		mutex_unlock(&cmem_mutex);
		kfree(entry);

		return -ENOMEM;
	    }

	    virtp = (unsigned long)page_address(page);
	    physp = page_to_pfn(page) << PAGE_SHIFT;

	    entry->start_page = page;
	    entry->count = count;
	    entry->physp = physp;
	    entry->size = size;
	    entry->flags = cmd & ~CMEM_IOCCMDMASK;
	    INIT_LIST_HEAD(&entry->users);

            busylistp = &cmem_p_objs[pool].busylist;
	    list_add_tail(&entry->element, busylistp);

	    user = kmalloc(sizeof(struct registered_user), GFP_KERNEL);
	    user->filp = filp;
	    list_add(&user->element, &entry->users);

            mutex_unlock(&cmem_mutex);

	    if ((cmd & CMEM_IOCCMDMASK) == CMEM_IOCALLOC) {
		    allocDesc.alloc_pool_outparams.physp = entry->physp;
		    allocDesc.alloc_pool_outparams.size = entry->size;

		    if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
			return -EFAULT;
		    }
	    }
	    else {
		    if (put_user(physp, argp)) {
			return -EFAULT;
		    }
	    }

            __D("ALLOC%s%s: allocated %#x size buffer at %#lx (phys address)\n",
	        (cmd & CMEM_IOCCMDMASK) == CMEM_IOCALLOCHEAP ? "HEAP" : "",
	        cmd & CMEM_CACHED ? "CACHED" : "", entry->size, entry->physp);

	    break;

        /*
         * argp contains either the user virtual address or the physical
	 * address of the buffer to free coming in, and contains the pool
	 * where it was freed from and the size of the block on return.
         */
        case CMEM_IOCFREE:
            __D("FREE%s%s ioctl received.\n",
	        cmd & CMEM_HEAP ? "HEAP" : "",
	        cmd & CMEM_PHYS ? "PHYS" : "");

	    if (!(cmd & CMEM_PHYS)) {
		if (get_user(virtp, argp)) {
		    return -EFAULT;
		}

		physp = get_phys(virtp);

		if (physp == ~(0L)) {
		    __E("FREE%s: Failed to convert virtual %#lx to physical\n",
			cmd & CMEM_HEAP ? "HEAP" : "", virtp);
		    return -EFAULT;
		}

		__D("FREE%s: translated %#lx user virtual to %#lx physical\n",
		    cmd & CMEM_HEAP ? "HEAP" : "", virtp, physp);
	    }
	    else {
		virtp = 0L;    /* silence the compiler warning */
		if (get_user(physp, argp)) {
		    return -EFAULT;
		}
	    }

	    if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
	    }

	    size = 0;

	    entry = find_busy_entry(physp, &pool, &e);
	    if (entry) {
		/* record values in case entry gets kfree()'d for CMEM_HEAP */
		size = entry->size;

		registeredlistp = &entry->users;
		u = registeredlistp->next;
		while (u != registeredlistp) {
		    unext = u->next;

		    user = list_entry(u, struct registered_user, element);
		    if (user->filp == filp) {
			__D("FREE%s%s: Removing file %p from user list of buffer %#lx...\n",
			    cmd & CMEM_HEAP ? "HEAP" : "",
			    cmd & CMEM_PHYS ? "PHYS" : "", filp, physp);

			list_del(u);
			kfree(user);

			break;
		    }

		    u = unext;
		}

		if (u == registeredlistp) {
		    __E("FREE%s%s: Not a registered user of physical buffer %#lx\n",
			cmd & CMEM_HEAP ? "HEAP" : "",
		        cmd & CMEM_PHYS ? "PHYS" : "", physp);
		    mutex_unlock(&cmem_mutex);

		    return -EFAULT;
		}

		if (registeredlistp->next == registeredlistp) {
		    /* no more registered users, free buffer */

		    page = entry->start_page;
		    count = entry->count;

		    list_del(e);
		    kfree(entry);

		    cmem_release(&cmem_dev[pool], page, count);

		    __D("FREE%s%s: Successfully freed buffer from pool %d\n",
			cmd & CMEM_HEAP ? "HEAP" : "",
			cmd & CMEM_PHYS ? "PHYS" : "", pool);
		}
	    }

            mutex_unlock(&cmem_mutex);

            if (!entry) {
                __E("Failed to free memory at %#lx\n", physp);
                return -EFAULT;
            }

#ifdef __DEBUG
            dump_lists(pool);
#endif

	    if (pool == heap_pool) {
		allocDesc.free_outparams.size = size;
	    }
	    else {
		allocDesc.free_outparams.size = cmem_p_objs[pool].size;
	    }
	    allocDesc.free_outparams.poolid = pool;
	    if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
                return -EFAULT;
            }

            __D("FREE%s%s: returning size %d, poolid %d\n",
	        cmd & CMEM_HEAP ? "HEAP" : "",
	        cmd & CMEM_PHYS ? "PHYS" : "",
		allocDesc.free_outparams.size,
		allocDesc.free_outparams.poolid);

            break;

        /*
         * argp contains the user virtual address of the buffer to translate
         * coming in, and the translated physical address on return.
         */
        case CMEM_IOCGETPHYS:
            __D("GETPHYS ioctl received.\n");
            if (get_user(virtp, argp)) {
                return -EFAULT;
            }

            physp = get_phys(virtp);

            if (physp == ~(0L)) {
                __E("GETPHYS: Failed to convert virtual %#lx to physical.\n",
                    virtp);
                return -EFAULT;
            }

            if (put_user(physp, argp)) {
                return -EFAULT;
            }

            __D("GETPHYS: returning %#lx\n", physp);
            break;

        /*
         * argp contains the pool to query for size coming in, and the size
         * of the pool on return.
         */
        case CMEM_IOCGETSIZE:
            __D("GETSIZE ioctl received\n");
	    if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
                return -EFAULT;
            }

	    pool = allocDesc.get_size_inparams.poolid;

            if (pool >= cmem_npools || pool < 0) {
                __E("GETSIZE: invalid pool (%d) passed.\n", pool);
                return -EINVAL;
            }

            if (put_user(cmem_p_objs[pool].size, argp)) {
                return -EFAULT;
            }
            __D("GETSIZE returning %d\n", cmem_p_objs[pool].size);
            break;

        /*
         * argp contains the requested pool buffers size coming in, and the
         * pool id (index) on return.
         */
        case CMEM_IOCGETPOOL:
            __D("GETPOOL ioctl received.\n");
	    if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
                return -EFAULT;
            }

	    reqsize = allocDesc.get_pool_inparams.size;

	    if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
	    }

            __D("GETPOOL: Trying to find a pool to fit size %d\n", reqsize);
            for (i = 1; i < cmem_npools; i++) {
                size = cmem_p_objs[i].size;

                __D("GETPOOL: size (%d) > reqsize (%d)?\n", size, reqsize);
                if (size >= reqsize) {
                    __D("GETPOOL: delta (%d) < olddelta (%d)?\n",
                        size - reqsize, delta);
                    if ((size - reqsize) < delta) {
			delta = size - reqsize;
			__D("GETPOOL: Found a best fit delta %d\n", delta);
			pool = i;
                    }
                }
            }

	    if (pool == -1 && cmem_heapsize != 0) {
		if (useHeapIfPoolUnavailable) {
		    /* no pool buffer available, try heap */

		    /*
		     * Indicate heap pool with magic negative value.
		     * -1 indicates no pool and no heap.
		     * -2 indicates no pool but heap available and allowed.
		     */
		    pool = -2;

		    __D("GETPOOL: no pool-based buffer available, "
			"returning heap \"pool\" instead (due to config "
			"override)\n");
		}
	    }

            mutex_unlock(&cmem_mutex);

	    if (pool == -1) {
		__E("Failed to find a pool which fits %d\n", reqsize);

		return -ENOMEM;
            }

            if (put_user(pool, argp)) {
                return -EFAULT;
            }
            __D("GETPOOL: returning %d\n", pool);
            break;

        case CMEM_IOCCACHE:
            __D("CACHE%s%s ioctl received.\n",
	        cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "");

	    if (copy_from_user(&block, argp, sizeof(block))) {
		return -EFAULT;
	    }
	    virtp = block.addr;
	    virtp_end = virtp + block.size;

	    switch (cmd & ~CMEM_IOCMAGIC) {
	      case CMEM_IOCCACHEWB:
		dmac_map_area((void *)virtp, block.size, DMA_TO_DEVICE);
		outer_clean_range(__pa((u32)(void *)virtp),
		                  __pa((u32)(void *)virtp + block.size));
		__D("CACHEWB: cleaned user virtual %#lx->%#lx\n",
		       virtp, virtp_end);

		break;

	      case CMEM_IOCCACHEINV:
		dmac_map_area((void *)virtp, block.size, DMA_FROM_DEVICE);
		outer_inv_range(__pa((u32)(void *)virtp),
		                __pa((u32)(void *)virtp + block.size));
		__D("CACHEINV: invalidated user virtual %#lx->%#lx\n",
		       virtp, virtp_end);

		break;

	      case CMEM_IOCCACHEWBINV:
		dmac_map_area((void *)virtp, block.size, DMA_BIDIRECTIONAL);
		outer_flush_range(__pa((u32)(void *)virtp),
		                  __pa((u32)(void *)virtp + block.size));
		__D("CACHEWBINV: flushed user virtual %#lx->%#lx\n",
		       virtp, virtp_end);

		break;
	    }

	    break;

        case CMEM_IOCGETVERSION:
            __D("GETVERSION ioctl received, returning %#x.\n", version);

            if (put_user(version, argp)) {
                return -EFAULT;
            }

	    break;

        case CMEM_IOCREGUSER:
            __D("REGUSER ioctl received.\n");

	    if (get_user(physp, argp)) {
		return -EFAULT;
	    }

	    if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
	    }

	    entry = find_busy_entry(physp, &pool, &e);
	    if (entry) {
		/*
		 * Should we check if the "current" process is already on
		 * the list and return error if so?  Or should we just
		 * silently not put it on the list twice and return success?
		 * Or should we put it on the list a second time, which seems
		 * to be OK to do and will require being removed from the
		 * list twice?  So many questions...
		 *
		 * The code below, lacking the test, will put a process on
		 * the list multiple times (every time IOCREGUSER is called).
		 */
		user = kmalloc(sizeof(struct registered_user), GFP_KERNEL);
		user->filp = filp;
		list_add(&user->element, &entry->users);
	    }

            mutex_unlock(&cmem_mutex);

            if (!entry) {
                return -EFAULT;
            }

            if (put_user(entry->size, argp)) {
                return -EFAULT;
            }

	    break;

        default:
            __E("Unknown ioctl received.\n");
            return -EINVAL;
    }

    return 0;
}

static int mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long physp;
    struct pool_buffer *entry;

    __D("mmap: vma->vm_start     = %#lx\n", vma->vm_start);
    __D("mmap: vma->vm_pgoff     = %#lx\n", vma->vm_pgoff);
    __D("mmap: vma->vm_end       = %#lx\n", vma->vm_end);
    __D("mmap: size              = %#lx\n", vma->vm_end - vma->vm_start);

    physp = vma->vm_pgoff << PAGE_SHIFT;

    if (mutex_lock_interruptible(&cmem_mutex)) {
	return -ERESTARTSYS;
    }

    entry = find_busy_entry(physp, NULL, NULL);
    mutex_unlock(&cmem_mutex);

    if (entry != NULL) {
	if (entry->flags & CMEM_CACHED) {
	    __D("mmap: calling set_cached(%p) ...\n", vma);

	    return set_cached(vma);
	}
	else {
	    __D("mmap: calling set_noncached(%p) ...\n", vma);

	    return set_noncached(vma);
	}
    }
    else {
	__E("mmap: can't find allocated buffer with physp %lx\n", physp);

	return -EINVAL;
    }
}

static int open(struct inode *inode, struct file *filp)
{
    __D("open: called.\n");

    atomic_inc(&reference_count);

    return 0;
}

static int release(struct inode *inode, struct file *filp)
{
    struct list_head *registeredlistp;
    struct list_head *busylistp;
    struct list_head *e;
    struct list_head *u;
    struct list_head *next;
    struct list_head *unext;
    struct page *page;
    struct pool_buffer *entry;
    struct registered_user *user;
    int last_close = 0;
    int count;
    int i;

    __D("close: called.\n");

    /* Force free all buffers owned by the 'current' process */

    if (atomic_dec_and_test(&reference_count)) {
        __D("close: all references closed, force freeing all busy buffers.\n");

	last_close = 1;
    }

    /* Clean up any buffers on the busy list when cmem is closed */
    for (i = 0; i < cmem_npools; i++) {
	__D("Forcing free on pool %d\n", i);

	/* acquire the mutex in case this isn't the last close */
	if (mutex_lock_interruptible(&cmem_mutex)) {
	    return -ERESTARTSYS;
	}

	busylistp = &cmem_p_objs[i].busylist;

	e = busylistp->next;
	while (e != busylistp) {
	    __D("busy entry(s) found\n");

	    next = e->next;

	    entry = list_entry(e, struct pool_buffer, element);
	    registeredlistp = &entry->users;
	    u = registeredlistp->next;
	    while (u != registeredlistp) {
		unext = u->next;

		user = list_entry(u, struct registered_user, element);

		if (last_close || user->filp == filp) {
		    __D("Removing file %p from user list of buffer %#lx...\n",
			user->filp, entry->physp);

		    list_del(u);
		    kfree(user);
		}

		u = unext;
	    }

	    if (registeredlistp->next == registeredlistp) {
		/* no more registered users, free buffer */

		__D("Warning: Freeing 'busy' buffer at %#lx\n",
		    entry->physp);

		page = entry->start_page;
		count = entry->count;
		cmem_release(&cmem_dev[i], page, count);

		list_del(e);
		kfree(entry);
	    }

	    e = next;
	}

	mutex_unlock(&cmem_mutex);
    }

    __D("close: returning\n");

    return 0;
}

static void banner(void)
{
    printk(KERN_INFO "CMEMK module: built on " __DATE__ " at " __TIME__ "\n");
    printk(KERN_INFO "  Reference Linux version %d.%d.%d\n",
           (LINUX_VERSION_CODE & 0x00ff0000) >> 16,
           (LINUX_VERSION_CODE & 0x0000ff00) >> 8,
           (LINUX_VERSION_CODE & 0x000000ff) >> 0
          );
    printk(KERN_INFO "  File " __FILE__ "\n");
}

#if 0
void __init cmem_test_init(void)
{
    printk("cmem_test_init(): calling test_dma_contig(1, 0)...\n");

    test_dma_contig(1, 0);
#if 0
    test_dma_contig(2, 0);
    test_dma_contig(4, 0);
    test_dma_contig(1, 1);
    test_dma_contig(2, 1);
    test_dma_contig(4, 1);
    test_dma_contig(1, 2);
    test_dma_contig(2, 2);
    test_dma_contig(4, 2);
#endif
    test_dma_contig(1, 3); // order 3 = pages aligned to 0x8000
    test_dma_contig(8, 3);
    test_dma_contig(9, 3);
    test_dma_contig(16, 3);

    printk("...done\n");
}
#endif

struct device dev;

int __init cmem_init(void)
{
    int i;
    int err;

    banner();

    mutex_init(&cmem_mutex);

    cmem_major = register_chrdev(0, "cmem", &cmem_fxns);
    if (cmem_major < 0) {
        __E("Failed to allocate major number.\n");
        return -ENODEV;
    }

    __D("Allocated major number: %d\n", cmem_major);

    cmem_class = class_create(THIS_MODULE, "cmem");
    if (IS_ERR(cmem_class)) {
        __E("Error creating cmem device class.\n");
	err = -EIO;
	goto fail_after_reg;
    }

    dev.devt = MKDEV(cmem_major, 0);
    dev.class = cmem_class;
    dev_set_name(&dev, "cmem");

    err = device_register(&dev);
    if (err) {
	__E("Unable to register dev\n");
	err = -EIO;
	goto fail_after_class;
    }

    for (i = 0; i < cmem_npools; i++) {
	cmem_dev[i].devt = MKDEV(cmem_major, i+1);
	cmem_dev[i].class = cmem_class;
	dev_set_name(&cmem_dev[i], "cmem%d", i+1);

	err = device_register(&cmem_dev[i]);
	if (err) {
	    __E("Unable to register cmem_dev[i]\n");
	    err = -EIO;
	    goto fail_after_class;
	}
    }

#if 0
    cmem_test_init();
#endif

    /* Create the /proc entry */
    cmem_proc_entry = create_proc_entry("cmem", 0, NULL);
    if (cmem_proc_entry) {
//	cmem_proc_entry->proc_fops = &cmem_proc_ops;
    }

    printk(KERN_INFO "cmemk initialized\n");

    return 0;

fail_after_class:
    __D("Destroying class cmem\n");
    class_destroy(cmem_class);

fail_after_reg:
    __D("Unregistering character device cmem\n");
    unregister_chrdev(cmem_major, "cmem");

    return err;
}

void __exit cmem_exit(void)
{
    struct list_head *registeredlistp;
    struct list_head *busylistp;
    struct list_head *e;
    struct list_head *u;
    struct list_head *unext;
    struct pool_buffer *entry;
    struct registered_user *user;
    int i;

    __D("In cmem_exit()\n");

    /* Remove the /proc entry */
    remove_proc_entry("cmem", NULL);

    /* Free the pool structures and empty the lists. */
    for (i = 0; i < cmem_npools; i++) {
	__D("Freeing memory associated with pool %d\n", i);

	busylistp = &cmem_p_objs[i].busylist;

	e = busylistp->next;
	while (e != busylistp) {
	    entry = list_entry(e, struct pool_buffer, element);

	    __D("Warning: Freeing busy entry at %#lx\n", entry->physp);

	    registeredlistp = &entry->users;
	    u = registeredlistp->next;
	    while (u != registeredlistp) {
		unext = u->next;

		user = list_entry(u, struct registered_user, element);

		__D("Removing file %p from user list of buffer %#lx...\n",
		    user->filp, entry->physp);

		list_del(u);
		kfree(user);

		u = unext;
	    }

	    e = e->next;
	    kfree(entry);
	}
    }

    for (i = 0; i < cmem_npools; i++) {
	__D("Unregistering device minor %d\n", i);
	device_unregister(&cmem_dev[i]);
    }

    __D("Destroying class cmem\n");
    class_destroy(cmem_class);

    __D("Unregistering character device cmem\n");
    unregister_chrdev(cmem_major, "cmem");

    printk(KERN_INFO "cmemk unregistered\n");
}

MODULE_LICENSE("GPL");
module_init(cmem_init);
module_exit(cmem_exit);


#if !defined(MULTI_CACHE)

#warning "MULTI_CACHE is *not* #defined, using work-around for asm cache functions"

/*
 * The following assembly functions were taken from
 *     arch/arm/mm/proc-arm926.S
 * Since we can't use the C preprocessor to evaluate #defines, the
 * code that was taken is the code encapsulated by
 *     #ifndef CONFIG_CPU_DCACHE_WRITETHROUGH
 *     ...
 *     #endif
 * (note that this is #ifndef, i.e., #if !defined)
 */

/*
 * the cache line size of the I and D cache
 */
/*
 * Leave here for documentation purposes, but we don't use it since
 * asm("") statements won't get preprocessed (inside a string).
 */
#define CACHE_DLINESIZE 32

asm("\n \
        .global arm926_dma_map_area\n \
arm926_dma_map_area:\n \
        add     r1, r1, r0\n \
@        cmp     r2, #DMA_TO_DEVICE\n \
        cmp     r2, #1\n \
        beq     arm926_dma_clean_range\n \
        bcs     arm926_dma_inv_range\n \
        b       arm926_dma_flush_range\n \
");

/*
 *      dma_inv_range(start, end)
 *
 *      Invalidate (discard) the specified virtual address range.
 *      May not write back any entries.  If 'start' or 'end'
 *      are not cache line aligned, those lines must be written
 *      back.
 *
 *      - start - virtual start address
 *      - end   - virtual end address
 *
 * (same as v4wb)
ENTRY(arm926_dma_inv_range)
 */
asm("\n \
	.global arm926_dma_inv_range\n \
arm926_dma_inv_range:\n \
@        tst     r0, #CACHE_DLINESIZE - 1\n \
        tst     r0, #32 - 1\n \
        mcrne   p15, 0, r0, c7, c10, 1          @ clean D entry\n \
@        tst     r1, #CACHE_DLINESIZE - 1\n \
        tst     r1, #32 - 1\n \
        mcrne   p15, 0, r1, c7, c10, 1          @ clean D entry\n \
@        bic     r0, r0, #CACHE_DLINESIZE - 1\n \
        bic     r0, r0, #32 - 1\n \
1:      mcr     p15, 0, r0, c7, c6, 1           @ invalidate D entry\n \
@        add     r0, r0, #CACHE_DLINESIZE\n \
        add     r0, r0, #32\n \
        cmp     r0, r1\n \
        blo     1b\n \
        mcr     p15, 0, r0, c7, c10, 4          @ drain WB\n \
        mov     pc, lr\n \
");

/*
 *      dma_clean_range(start, end)
 *
 *      Clean the specified virtual address range.
 *
 *      - start - virtual start address
 *      - end   - virtual end address
 *
 * (same as v4wb)
ENTRY(arm926_dma_clean_range)
 */
asm("\n \
	.global arm926_dma_clean_range\n \
arm926_dma_clean_range:\n \
@        bic     r0, r0, #CACHE_DLINESIZE - 1\n \
        bic     r0, r0, #32 - 1\n \
1:      mcr     p15, 0, r0, c7, c10, 1          @ clean D entry\n \
@        add     r0, r0, #CACHE_DLINESIZE\n \
        add     r0, r0, #32\n \
        cmp     r0, r1\n \
        blo     1b\n \
        mcr     p15, 0, r0, c7, c10, 4          @ drain WB\n \
        mov     pc, lr\n \
");

/*
 *      dma_flush_range(start, end)
 *
 *      Clean and invalidate the specified virtual address range.
 *
 *      - start - virtual start address
 *      - end   - virtual end address
ENTRY(arm926_dma_flush_range)
 */
asm("\n \
	.global arm926_dma_flush_range\n \
arm926_dma_flush_range:\n \
@        bic     r0, r0, #CACHE_DLINESIZE - 1\n \
        bic     r0, r0, #32 - 1\n \
1:\n \
        mcr     p15, 0, r0, c7, c14, 1          @ clean+invalidate D entry\n \
@        add     r0, r0, #CACHE_DLINESIZE\n \
        add     r0, r0, #32\n \
        cmp     r0, r1\n \
        blo     1b\n \
        mcr     p15, 0, r0, c7, c10, 4          @ drain WB\n \
        mov     pc, lr\n \
");

#endif /* !defined(MULTI_CACHE) */

