/*
 *  Copyright (C) 2007-2018 Texas Instruments Incorporated - http://www.ti.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
/*
 * cmemk.c
 */

#include <linux/version.h>
#include <linux/device.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#else
#include <linux/dma-map-ops.h>
#endif
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#include <ti/cmem.h>

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/dma-buf.h>

/*
 * USE_MMAPSEM means acquire/release current->mm->mmap_sem around calls
 * to dma_[flush/clean/inv]_range.
 */
//#define USE_MMAPSEM

/*
 * CHECK_FOR_ALLOCATED_BUFFER means ensure that the passed addr/size block
 * is actually an allocated, CMEM-defined buffer.
 */
//#define CHECK_FOR_ALLOCATED_BUFFER

/* HEAP_ALIGN is used in place of sizeof(HeapMem_Header) */
#define HEAP_ALIGN PAGE_SIZE


#ifdef __DEBUG
#define __D(fmt, args...) printk(KERN_DEBUG "CMEMK Debug: " fmt, ## args)
#else
#define __D(fmt, args...)
#endif

#define __E(fmt, args...) printk(KERN_ERR "CMEMK Error: " fmt, ## args)

#define MAXTYPE(T) ((T) (((T)1 << ((sizeof(T) * 8) - 1) ^ ((T) -1))))

/*
 * Change here for supporting more than 4 blocks.  Also change all
 * NBLOCKS-based arrays to have NBLOCKS-worth of initialization values.
 */
#define NBLOCKS 4

#define BLOCK_IOREMAP    (1 << 0)
#define BLOCK_MEMREGION  (1 << 1)
#define BLOCK_REGION     (1 << 2)

#ifndef VM_RESERVED
#define VM_RESERVED 0x00080000
#endif

/* Define types of blocks */
#define BLOCK_TYPE_RESV_MEMORY_NODE 0
#define BLOCK_TYPE_SRAM_NODE   1

static unsigned int nblocks = 0;
static unsigned int block_flags[NBLOCKS] = {0, 0, 0, 0};
static unsigned long long block_start[NBLOCKS] = {0, 0, 0, 0};
static unsigned long long block_end[NBLOCKS] = {0, 0, 0, 0};
static unsigned long long block_avail_size[NBLOCKS] = {0, 0, 0, 0};
static int block_type[NBLOCKS] = {0, 0, 0 , 0}; 
static unsigned int total_num_buffers[NBLOCKS] = {0, 0, 0, 0};
static int pool_num_buffers[NBLOCKS][MAX_POOLS];
static unsigned long long pool_size[NBLOCKS][MAX_POOLS];

static int cmem_major;
static struct proc_dir_entry *cmem_proc_entry;
static atomic_t reference_count = ATOMIC_INIT(0);
static unsigned int version = CMEM_VERSION;

static struct class *cmem_class;

/* Register the module parameters. */
MODULE_PARM_DESC(phys_start, "\n\t\t Start Address for CMEM Pool Memory");
static char *phys_start = NULL;
MODULE_PARM_DESC(phys_end, "\n\t\t End Address for CMEM Pool Memory");
static char *phys_end = NULL;
module_param(phys_start, charp, S_IRUGO);
module_param(phys_end, charp, S_IRUGO);

static int npools[NBLOCKS + 1] = {0, 0, 0, 0, 0};

static char *pools[MAX_POOLS] = {
	NULL
};
MODULE_PARM_DESC(pools,
		 "\n\t\t List of Pool Sizes and Number of Entries, comma separated,"
		 "\n\t\t decimal sizes");
module_param_array(pools, charp, &npools[0], S_IRUGO);

/* begin block 1 */
MODULE_PARM_DESC(phys_start_1, "\n\t\t Start Address for Extended CMEM Pool Memory");
static char *phys_start_1 = NULL;
MODULE_PARM_DESC(phys_end_1, "\n\t\t End Address for Extended CMEM Pool Memory");
static char *phys_end_1 = NULL;
module_param(phys_start_1, charp, S_IRUGO);
module_param(phys_end_1, charp, S_IRUGO);

static char *pools_1[MAX_POOLS] = {
	NULL
};
MODULE_PARM_DESC(pools_1,
	"\n\t\t List of Pool Sizes and Number of Entries, comma separated,"
	"\n\t\t decimal sizes, for Extended CMEM Pool");
module_param_array(pools_1, charp, &npools[1], S_IRUGO);
/* end block 1 */

/* begin block 2 */
MODULE_PARM_DESC(phys_start_2, "\n\t\t Start Address for Extended CMEM Pool Memory");
static char *phys_start_2 = NULL;
MODULE_PARM_DESC(phys_end_2, "\n\t\t End Address for Extended CMEM Pool Memory");
static char *phys_end_2 = NULL;
module_param(phys_start_2, charp, S_IRUGO);
module_param(phys_end_2, charp, S_IRUGO);

static char *pools_2[MAX_POOLS] = {
	NULL
};
MODULE_PARM_DESC(pools_2,
		 "\n\t\t List of Pool Sizes and Number of Entries, comma separated,"
		 "\n\t\t decimal sizes, for Extended CMEM Pool");
module_param_array(pools_2, charp, &npools[2], S_IRUGO);
/* end block 2 */

/* cut-and-paste below as part of adding support for more than 4 blocks */
/* begin block 3 */
MODULE_PARM_DESC(phys_start_3, "\n\t\t Start Address for Extended CMEM Pool Memory");
static char *phys_start_3 = NULL;
MODULE_PARM_DESC(phys_end_3, "\n\t\t End Address for Extended CMEM Pool Memory");
static char *phys_end_3 = NULL;
module_param(phys_start_3, charp, S_IRUGO);
module_param(phys_end_3, charp, S_IRUGO);

static char *pools_3[MAX_POOLS] = {
	NULL
};
MODULE_PARM_DESC(pools_3,
	"\n\t\t List of Pool Sizes and Number of Entries, comma separated,"
	"\n\t\t decimal sizes, for Extended CMEM Pool");
module_param_array(pools_3, charp, &npools[3], S_IRUGO);
/* end block 3 */
/* cut-and-paste above as part of adding support for more than 4 blocks */

static int allowOverlap = -1;
MODULE_PARM_DESC(allowOverlap,
		 "\n\t\t DEPRECATED - ignored if found"
		 "\n\t\t Set to 1 if cmem range is allowed to overlap memory range"
		 "\n\t\t allocated to kernel physical mem (via mem=xxx)");
module_param(allowOverlap, int, S_IRUGO);

static int useHeapIfPoolUnavailable = 0;
MODULE_PARM_DESC(useHeapIfPoolUnavailable,
		 "\n\t\t Set to 1 if you want a pool-based allocation request to"
		 "\n\t\t fall back to a heap-based allocation attempt");
module_param(useHeapIfPoolUnavailable, int, S_IRUGO);

static struct mutex cmem_mutex;

/* Describes a pool buffer */
typedef struct pool_buffer {
	struct list_head element;
	struct list_head users;
	dma_addr_t dma;			/* used only for CMA-based allocs */
	int id;
	phys_addr_t physp;
	int flags;			/* CMEM_CACHED or CMEM_NONCACHED */
	void *kvirtp;			/* used only for CMA-based allocs or exported buffers*/
	unsigned long long size;	/* used only for heap-based allocs */
	struct device *dev;		/* used only for CMA-based allocs */
	struct vm_struct *vma;
} pool_buffer;

typedef struct registered_user {
	struct list_head element;
	struct file *filp;
} registered_user;

struct cmem_dmabuf_attachment {
	struct sg_table *sgt;
	enum dma_data_direction dir;
};

#ifdef CMEM_KERNEL_STUB

#include <linux/cmemk_stub.h>

typedef struct pool_object pool_object;

#else

/* Describes a pool */
typedef struct pool_object {
	struct list_head freelist;
	struct list_head busylist;
	unsigned int numbufs;
	unsigned long long size;
	unsigned long long reqsize;
} pool_object;

static int cmem_cma_npools = 0;
static int cmem_cma_heapsize = 0;
static struct device *cmem_cma_dev;
static struct pool_object *cmem_cma_p_objs;
#endif

static struct device *cmem_cma_dev_0;
#if IS_ENABLED(CONFIG_ARCH_KEYSTONE) && IS_ENABLED(CONFIG_ARM_LPAE) \
	&& (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
#define KEYSTONE_DMA_PFN_OFFSET 0x780000UL

/* definitions from arch/arm/mach-keystone/memory.h */
#define KEYSTONE_LOW_PHYS_START         0x80000000ULL
#define KEYSTONE_HIGH_PHYS_START        0x800000000ULL
#define KEYSTONE_HIGH_PHYS_SIZE		0x400000000ULL	/* 16G */
#endif

#if IS_ENABLED(CONFIG_ARCH_K3)
#define DISABLE_CACHE_OPERATIONS
#else
#if !defined(dmac_map_area)
#if !defined(MULTI_CACHE)
/* Add prototypes for dmac_map_area */
#define dmac_map_area                   __glue(_CACHE,_dma_map_area)
void dmac_map_area(const void *, size_t, int);
#endif
#endif
#endif

/*
 * For CMA allocations we treat p_objs[NBLOCKS] as a special "pool" array.
 */
static pool_object p_objs[NBLOCKS + 1][MAX_POOLS];


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


/*
 *  NOTE: The following implementation of a heap is taken from the
 *  DSP/BIOS 6.0 source tree (avala-f15/src/ti/sysbios/heaps).  Changes
 *  are necessary due to the fact that CMEM is not built in an XDC
 *  build environment, and therefore XDC types and helper APIs (e.g.,
 *  Assert) are not available.  However, these changes were kept to a
 *  minimum.
 *
 *  The changes include:
 *	- renaming XDC types to standard C types
 *	- replacing sizeof(HeapMem_Header) w/ HEAP_ALIGN throughout
 *
 *  As merged with CMEM, the heap becomes a distinguished "pool" and
 *  is sometimes treated specially, and at other times can be treated
 *  as a normal pool instance.
 */

/*
 * HeapMem compatibility stuff
 */
typedef struct HeapMem_Header {
	phys_addr_t next;
	size_t size;
} HeapMem_Header;

#define ALLOCRUN 0
#define DRYRUN 1

phys_addr_t HeapMem_alloc(int bi, size_t size, size_t align, int dryrun);
void HeapMem_free(int bi, phys_addr_t block, size_t size);

/*
 * Heap configuration stuff
 *
 * For CMA global heap allocations, we treat heap_pool[NBLOCKS] as
 * its own block.  For example, if you have 4 physically-specified
 * blocks then NBLOCKS = 4.  heap_pool[0]|[1]|[2]|[3] are the real blocks, and
 * heap_pool[4] represents the global CMA area.
 *
 * Only heap_pool[] gets extended with NBLOCKS + 1 dimension, since the
 * other heap_*[] arrays are used only with the real blocks.  You can't
 * use heap_pool[NBLOCKS] for HeapMem_alloc().
 */
static int heap_pool[NBLOCKS + 1] = {-1, -1, -1, -1, 0};

static unsigned long heap_size[NBLOCKS] = {0, 0, 0, 0};
static phys_addr_t heap_physp[NBLOCKS] = {0, 0, 0, 0};
static HeapMem_Header heap_head[NBLOCKS] = {
	{
		0,	/* next */
		0	/* size */
	},
	{
		0,	/* next */
		0	/* size */
	},
	{
		0,	/* next */
		0	/* size */
	},
/* cut-and-paste below as part of adding support for more than 4 blocks */
	{
		0,	/* next */
		0	/* size */
	},
/* cut-and-paste above as part of adding support for more than 4 blocks */
};

static int map_header(void **vaddrp, phys_addr_t physp)
{
	void *vaddr;

	vaddr = ioremap((resource_size_t)physp, PAGE_SIZE);
	if (vaddr == NULL) {
		__E("map_header: ioremap(%#llx, %#llx) failed \n",
		    (unsigned long long)physp,
		    (unsigned long long)PAGE_SIZE);
		return -ENOMEM;
	}
	*vaddrp = vaddr;

	__D("map_header: ioremap(%#llx, %#llx)=0x%p\n",
	(unsigned long long)physp, (unsigned long long)PAGE_SIZE, *vaddrp);


	return 0;
}

static void unmap_header(void *vaddr)
{
	__D("unmap_header: unmap_kernel_page_rage(0x%p, %#lx)\n", vaddr, PAGE_SIZE);

	iounmap(vaddr);
}

/*
 *  ======== HeapMem_alloc ========
 *  HeapMem is implemented such that all of the memory and blocks it works
 *  with have an alignment that is a multiple of HEAP_ALIGN and have a size
 *  which is a multiple of HEAP_ALIGN. Maintaining this requirement
 *  throughout the implementation ensures that there are never any odd
 *  alignments or odd block sizes to deal with.
 *
 *  Specifically:
 *  The buffer managed by HeapMem:
 *    1. Is aligned on a multiple of HEAP_ALIGN
 *    2. Has an adjusted size that is a multiple of HEAP_ALIGN
 *  All blocks on the freelist:
 *    1. Are aligned on a multiple of HEAP_ALIGN
 *    2. Have a size that is a multiple of HEAP_ALIGN
 *  All allocated blocks:
 *    1. Are aligned on a multiple of HEAP_ALIGN
 *    2. Have a size that is a multiple of HEAP_ALIGN
 *
 */
phys_addr_t HeapMem_alloc(int bi, size_t reqSize, size_t reqAlign, int dryrun)
{
	HeapMem_Header *curHeader;
	HeapMem_Header *prevHeader;
	HeapMem_Header *newHeader;
	phys_addr_t curHeaderPhys;
	phys_addr_t prevHeaderPhys = 0;
	phys_addr_t newHeaderPhys = 0;  /* init to quiet compiler */
	phys_addr_t allocAddr;
	size_t curSize, adjSize;
	size_t remainSize;  /* free memory after allocated memory */
	size_t adjAlign, offset;
	int ret_value;

	adjSize = reqSize;

	/* Make size requested a multiple of HEAP_ALIGN */
	if ((offset = (adjSize & (HEAP_ALIGN - 1))) != 0) {
		adjSize = adjSize + (HEAP_ALIGN - offset);
	}

	/*
	 *  Make sure the alignment is at least as large as HEAP_ALIGN.
	 *  Note: adjAlign must be a power of 2 (by function constraint) and
	 *  HEAP_ALIGN is also a power of 2,
	 */
	adjAlign = reqAlign;
	if (adjAlign & (HEAP_ALIGN - 1)) {
		/* adjAlign is less than HEAP_ALIGN */
		adjAlign = HEAP_ALIGN;
	}

	/*
	 * The block will be allocated from curHeader. Maintain a pointer to
	 * prevHeader so prevHeader->next can be updated after the alloc.
	 */
	curHeaderPhys = heap_head[bi].next;

	/* Loop over the free list. */
	while (curHeaderPhys != 0) {
		ret_value = map_header((void **)&curHeader, curHeaderPhys);
		if (ret_value < 0) {
			return 0;
		}
		curSize = curHeader->size;

		/*
		 *  Determine the offset from the beginning to make sure
		 *  the alignment request is honored.
		 */
		offset = (unsigned long)curHeaderPhys & (adjAlign - 1);
		if (offset) {
			offset = adjAlign - offset;
		}

		/* big enough? */
		if (curSize >= (adjSize + offset)) {
			/* Set the pointer that will be returned. Alloc from front */
			allocAddr = curHeaderPhys + offset;

			if (dryrun) {
				return allocAddr;
			}

			/*
			 *  Determine the remaining memory after the allocated block.
			 *  Note: this cannot be negative because of above comparison.
			 */
			remainSize = curSize - adjSize - offset;

			if (remainSize) {
				newHeaderPhys = allocAddr + adjSize;
				ret_value = map_header((void **)&newHeader, newHeaderPhys);
				if (ret_value < 0)
					return 0;

				newHeader->next = curHeader->next;
				newHeader->size = remainSize;

				unmap_header(newHeader);
			}

			/*
			 *  If there is memory at the beginning (due to alignment
			 *  requirements), maintain it in the list.
			 *
			 *  offset and remainSize must be multiples of
			 *  HEAP_ALIGN. Therefore the address of the newHeader
			 *  below must be a multiple of the HEAP_ALIGN, thus
			 *  maintaining the requirement.
			 */
			if (offset) {
				/* Adjust the curHeader size accordingly */
				curHeader->size = offset;

				/*
				 *  If there is remaining memory, add into the free list.
				 *  Note: no need to coalesce and we have HeapMem locked so
				 *		it is safe.
				 */
				if (remainSize) {
					curHeader->next = newHeaderPhys;
				}
			}
			else {
				/*
				 *  If there is any remaining, link it in,
				 *  else point to the next free block.
				 *  Note: no need to coalesce and we have HeapMem locked so
				 *        it is safe.
				 */
				if (prevHeaderPhys != 0) {
					ret_value = map_header((void **)&prevHeader, prevHeaderPhys);
					if (ret_value < 0)
						return 0;
				}
				else {
					prevHeader = &heap_head[bi];
				}

				if (remainSize) {
					prevHeader->next = newHeaderPhys;
				}
				else {
					prevHeader->next = curHeader->next;
				}

				if (prevHeader != &heap_head[bi]) {
					unmap_header(prevHeader);
				}
			}

			unmap_header(curHeader);

			/* Success, return the allocated memory */
			return allocAddr;
		}
		else {
			prevHeaderPhys = curHeaderPhys;
			curHeaderPhys = curHeader->next;

			unmap_header(curHeader);
		}
	}

	return 0;
}

/*
 *  ======== HeapMem_free ========
 */
void HeapMem_free(int bi, phys_addr_t block, size_t size)
{
	HeapMem_Header *curHeader;
	HeapMem_Header *newHeader;
	HeapMem_Header *nextHeader;
	phys_addr_t curHeaderPhys = 0;
	phys_addr_t newHeaderPhys;
	phys_addr_t nextHeaderPhys;
	size_t offset;
	int ret_value;

	/* Restore size to actual allocated size */
	if ((offset = size & (HEAP_ALIGN - 1)) != 0) {
		size += HEAP_ALIGN - offset;
	}

	newHeaderPhys = block;
	nextHeaderPhys = heap_head[bi].next;

	/* Go down freelist and find right place for buf */
	while (nextHeaderPhys != 0 && nextHeaderPhys < newHeaderPhys) {
		ret_value = map_header((void **)&nextHeader, nextHeaderPhys);
		if (ret_value < 0)
			return;

		curHeaderPhys = nextHeaderPhys;
		nextHeaderPhys = nextHeader->next;

		unmap_header(nextHeader);
	}

	ret_value = map_header((void **)&newHeader, newHeaderPhys);
	if (ret_value < 0)
		return;

	if (curHeaderPhys != 0) {
		ret_value = map_header((void **)&curHeader, curHeaderPhys);
		if (ret_value < 0)
			return;
		}
	else {
		curHeader = &heap_head[bi];
	}

	newHeader->next = nextHeaderPhys;
	newHeader->size = size;
	curHeader->next = newHeaderPhys;

	/* Join contiguous free blocks */
	/* Join with upper block */
	if (nextHeaderPhys != 0 && (newHeaderPhys + size) == nextHeaderPhys) {
		ret_value = map_header((void **)&nextHeader, nextHeaderPhys);
		if (ret_value < 0)
			return;
		newHeader->next = nextHeader->next;
		newHeader->size += nextHeader->size;

		unmap_header(nextHeader);
	}

	/*
	 * Join with lower block. Make sure to check to see if not the
	 * first block.
	 */
	if (curHeader != &heap_head[bi]) {
		if ((curHeaderPhys + curHeader->size) == newHeaderPhys) {
			curHeader->next = newHeader->next;
			curHeader->size += newHeader->size;
		}

		unmap_header(curHeader);
	}

	unmap_header(newHeader);
}

static inline void cmem_mmap_read_lock(struct mm_struct *mm)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
	down_read(&mm->mmap_sem);
#else
	mmap_read_lock(mm);
#endif
}

static inline void cmem_mmap_read_unlock(struct mm_struct *mm)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
	up_read(&mm->mmap_sem);
#else
	mmap_read_unlock(mm);
#endif
}

/* Traverses the page tables and translates a virtual address to a physical. */
static phys_addr_t get_phys(void *virtp)
{
	unsigned long virt = (unsigned long)virtp;
	phys_addr_t physp = ~(0LL);
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	/* For kernel direct-mapped memory, take the easy way */
	if (virt >= PAGE_OFFSET) {
		physp = virt_to_phys(virtp);
		__D("get_phys: virt_to_phys translated direct-mapped %#lx to %#llx\n",
		    virt, (unsigned long long)physp);
		return(physp);
	}

	cmem_mmap_read_lock(current->mm);
	vma = find_vma(mm, virt);
	/* this will catch, kernel-allocated, mmaped-to-usermode addresses */
	if (vma  &&
	    (vma->vm_flags & VM_IO) &&
	    (vma->vm_pgoff)) {
		physp = (((phys_addr_t)vma->vm_pgoff) << PAGE_SHIFT) +
			(virt - vma->vm_start);
		cmem_mmap_read_unlock(current->mm);
		__D("get_phys: find_vma translated user %#lx to %pa\n", virt,
		    &physp);
		return(physp);
	}

	/* otherwise, use get_user_pages() for general userland pages */
	{
		int res, nr_pages = 1;
		struct page *pages;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0))
		res = get_user_pages_remote(current->mm, virt, nr_pages,
					    FOLL_WRITE, &pages, NULL, NULL);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
		res = get_user_pages_remote(current, current->mm, virt, nr_pages,
					    FOLL_WRITE, &pages, NULL, NULL);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
		res = get_user_pages_remote(current, current->mm, virt, nr_pages,
					    FOLL_WRITE, &pages, NULL);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0))
		res = get_user_pages_remote(current, current->mm, virt, nr_pages,
					    1, 0, &pages, NULL);
#else
		res = get_user_pages(current, current->mm, virt, nr_pages, 1, 0,
				     &pages, NULL);
#endif
		cmem_mmap_read_unlock(current->mm);

		if (res == nr_pages) {
			physp = __pa(page_address(&pages[0]) + (virt & ~PAGE_MASK));
			__D("get_phys: get_user_pages translated user %#lx to %pa\n",
			    virt, &physp);
		} else {
			__E("%s: Unable to find phys addr for %#lx\n",
				__FUNCTION__, virt);
			__E("%s: get_user_pages() failed: %d\n", __FUNCTION__, res);
		}
	}

	return physp;
}

/* Allocates space from the top "highmem" contiguous buffer for pool buffer. */
static phys_addr_t alloc_pool_buffer(int bi, unsigned long long size)
{
	phys_addr_t physp;

	__D("alloc_pool_buffer: Called for size 0x%llx\n", size);

	if (size <= block_avail_size[bi]) {
		__D("alloc_pool_buffer: Fits req %#llx < avail: %#llx\n",
			size, block_avail_size[bi]);
		block_avail_size[bi] -= size;
		physp = block_start[bi] + block_avail_size[bi];

		__D("alloc_pool_buffer: new available block size is %#llx\n",
			block_avail_size[bi]);

		__D("alloc_pool_buffer: returning allocated buffer at %#llx\n",
		(unsigned long long)physp);

		return physp;
	}

	__E("Failed to find a big enough free block\n");

	return 0;
}


#ifdef __DEBUG
/* Only for debug */
static void dump_lists(int bi, int idx)
{
	struct list_head *freelistp = &p_objs[bi][idx].freelist;
	struct list_head *busylistp = &p_objs[bi][idx].busylist;
	struct list_head *e;
	struct pool_buffer *entry;

/* way too chatty, neuter for now */
return;

	if (mutex_lock_interruptible(&cmem_mutex)) {
		return;
	}

	__D("Busylist for pool %d:\n", idx);
	for (e = busylistp->next; e != busylistp; e = e->next) {

		entry = list_entry(e, struct pool_buffer, element);
		if ( entry != NULL )
			__D("Busy: Buffer with id %d and physical address %#llx\n",
			    entry->id, (unsigned long long)entry->physp);
	}

	if (bi < NBLOCKS) {

		__D("Freelist for pool %d:\n", idx);
		for (e = freelistp->next; e != freelistp; e = e->next) {

			entry = list_entry(e, struct pool_buffer, element);
			if ( entry != NULL )
				__D("Free: Buffer with id %d and physical address %#llx\n",
				    entry->id, (unsigned long long)entry->physp);
		}
	}

	mutex_unlock(&cmem_mutex);
}
#endif

/*
 *  ======== find_busy_entry ========
 *  find_busy_entry looks for an allocated pool buffer containing
 *  physical addr physp -> (physp + *sizep).
 *
 *  Should be called with the cmem_mutex held.
 */
static struct pool_buffer *find_busy_entry(phys_addr_t physp, int *poolp, struct list_head **ep, int *bip, size_t *sizep)
{
	struct list_head *busylistp;
	struct list_head *e;
	struct pool_buffer *entry;
	int num_pools;
	int i;
	int bi;

	/* loop for NBLOCKS + 1 to handle special CMA global area "block" */
	for (bi = 0; bi < (NBLOCKS + 1); bi++) {
		num_pools = npools[bi];
		if (heap_pool[bi] != -1) {
			num_pools++;
		}

		for (i = 0; i < num_pools; i++) {
			busylistp = &p_objs[bi][i].busylist;

			for (e = busylistp->next; e != busylistp; e = e->next) {
				entry = list_entry(e, struct pool_buffer, element);
				if ((!sizep && entry->physp == physp) ||
				    (sizep &&
				     (physp >= entry->physp &&
				      (physp + *sizep) <= (entry->physp + entry->size)
				     )
				    )
				   ) {
					if (poolp) {
						*poolp = i;
					}
					if (ep) {
						*ep = e;
					}
					if (bip) {
						*bip = bi;
					}

					return entry;
				}
			}
		}
	}

	return NULL;
}

static void cmem_seq_stop(struct seq_file *s, void *v);
static void *cmem_seq_start(struct seq_file *s, loff_t *pos);
static void *cmem_seq_next(struct seq_file *s, void *v, loff_t *pos);
static int cmem_seq_show(struct seq_file *s, void *v);

static struct seq_operations cmem_seq_ops = {
	.start = cmem_seq_start,
	.next = cmem_seq_next,
	.stop = cmem_seq_stop,
	.show = cmem_seq_show,
};

#define SHOW_BUSY_BANNER (1 << 0)
#define SHOW_PREV_FREE_BANNER (1 << 1)
#define SHOW_LAST_FREE_BANNER (1 << 2)
#define BUSY_ENTRY (1 << 3)
#define FREE_ENTRY (1 << 4)

void *find_buffer_n(struct seq_file *s, int n)
{
	struct list_head *listp = NULL;
	int busy_empty;
	int free_empty = 0;
	int found = 0;
	int count;
	int i;
	int bi;

	__D("find_buffer_n: n=%d\n", n);

	s->private = (void *)0;
	count = 0;

	for (bi = 0; bi < NBLOCKS; bi++) {
		for (i = 0; i < npools[bi]; i++) {
			listp = &p_objs[bi][i].busylist;
			listp = listp->next;
			busy_empty = 1;
			while (listp != &p_objs[bi][i].busylist) {
				busy_empty = 0;
				if (count == n) {
					found = 1;
					s->private =
					    (void *)
					    ((uintptr_t)s->private
					     | BUSY_ENTRY);

					break;
				}
				count++;
				listp = listp->next;
			}
			if (found) {
				break;
			}

			listp = &p_objs[bi][i].freelist;
			listp = listp->next;
			free_empty = 1;
			while (listp != &p_objs[bi][i].freelist) {
				if (i == 0 ||
				    (p_objs[bi][i - 1].freelist.next !=
				     &p_objs[bi][i - 1].freelist)) {

					free_empty = 0;
				}
				if (count == n) {
					found = 1;
					s->private =
					    (void *)
					    ((uintptr_t)s->private
					     | FREE_ENTRY);

					break;
				}
				count++;
				listp = listp->next;
			}
			if (found) {
				break;
			}
		}
		if (found) {
			break;
		}
	}

	if (!found) {
		listp = NULL;
	}
	else {
		if (busy_empty) {
			s->private = (void *)
				     ((uintptr_t)s->private
				      | SHOW_BUSY_BANNER);
		}
		if (free_empty) {
			s->private = (void *)
				     ((uintptr_t)s->private
				      | SHOW_PREV_FREE_BANNER);
		}
		if (count == (total_num_buffers[bi] - 1)) {
			s->private = (void *)((uintptr_t)s->private
					      | SHOW_LAST_FREE_BANNER);
		}
	}

	return listp;
}

static void cmem_seq_stop(struct seq_file *s, void *v)
{
	__D("cmem_seq_stop: v=0x%p\n", v);

	mutex_unlock(&cmem_mutex);
}

static void *cmem_seq_start(struct seq_file *s, loff_t *pos)
{
	struct list_head *listp;
	int total_num;

	if (mutex_lock_interruptible(&cmem_mutex)) {
		return ERR_PTR(-ERESTARTSYS);
	}

	__D("cmem_seq_start: *pos=%d\n", (int)*pos);

	total_num = total_num_buffers[0] + total_num_buffers[1];
	if (*pos >= total_num) {
		__D("  %d >= %d\n", (int)*pos, total_num);

		return NULL;
	}

	listp = find_buffer_n(s, *pos);

	__D("  returning 0x%p\n", listp);

	return listp;
}

static void *cmem_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct list_head *listp;
	int total_num;

	__D("cmem_seq_next: *pos=%d\n", (int)*pos);

	__D("  incrementing *pos\n");
	++(*pos);

	total_num = total_num_buffers[0] + total_num_buffers[1];
	if (*pos >= total_num) {
		__D("  %d >= %d\n", (int)*pos, total_num);

		return NULL;
	}

	listp = find_buffer_n(s, *pos);

	__D("  returning 0x%p\n", listp);

	return listp;
}

void show_busy_banner(int bi, struct seq_file *s, int n)
{
	seq_printf(s, "\nBlock %d: Pool %d: %d bufs size 0x%llx"
		   " (0x%llx requested)\n\nPool %d busy bufs:\n",
		   bi, n, p_objs[bi][n].numbufs, p_objs[bi][n].size,
		   p_objs[bi][n].reqsize, n);
}

void show_free_banner(struct seq_file *s, int n)
{
	seq_printf(s, "\nPool %d free bufs:\n", n);
}

/*
 * Show one pool entry, w/ banners for first entries in a pool's busy or
 * free list.
 */
static int cmem_seq_show(struct seq_file *s, void *v)
{
	struct list_head *listp = v;
	struct list_head *e = v;
	struct pool_buffer *entry;
	char *attr;
	int i;
	int bi;

	__D("cmem_seq_show:\n");

	for (bi = 0; bi < NBLOCKS; bi++) {
		/* look for banners to show */
		for (i = 0; i < npools[bi]; i++) {
			if (listp == p_objs[bi][i].busylist.next) {
				/* first buffer in busylist */
				if ((uintptr_t)s->private
				    & SHOW_PREV_FREE_BANNER) {
					/*
					 * Previous pool's freelist empty, need to show banner.
					 */
					show_free_banner(s, i - 1);
				}
				show_busy_banner(bi, s, i);

				break;
			}
			if (listp == p_objs[bi][i].freelist.next) {
				/* first buffer in freelist */
				if ((uintptr_t)s->private
				    & SHOW_PREV_FREE_BANNER) {
					/*
					 * Previous pool's freelist & this pool's busylist empty,
					 * need to show banner.
					 */
					show_free_banner(s, i - 1);
				}
				if ((uintptr_t)s->private
				    & SHOW_BUSY_BANNER) {
					/*
					 * This pool's busylist empty, need to show banner.
					 */
					show_busy_banner(bi, s, i);
				}
				show_free_banner(s, i);

				break;
			}
		}
	}

	entry = list_entry(e, struct pool_buffer, element);

	if ((uintptr_t)s->private & BUSY_ENTRY) {
		attr = entry->flags & CMEM_CACHED ? "(cached)" : "(noncached)";
		seq_printf(s, "id %d: phys addr %#llx %s\n", entry->id,
			   (unsigned long long)entry->physp, attr);
	}
	else {
		seq_printf(s, "id %d: phys addr %#llx\n", entry->id,
			   (unsigned long long)entry->physp);
	}

	if ((uintptr_t)s->private & BUSY_ENTRY &&
		(uintptr_t)s->private & SHOW_LAST_FREE_BANNER) {

		/* FIXME */
		show_free_banner(s, npools[0] - 1);
	}

	return 0;
}

static int cmem_proc_open(struct inode *inode, struct file *file);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
static struct file_operations cmem_proc_fops = {
	.owner = THIS_MODULE,
	.open = cmem_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#else
static struct proc_ops cmem_proc_ops = {
	.proc_open = cmem_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release,
};
#endif

static int cmem_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cmem_seq_ops);
}

/* Allocate a contiguous memory pool. */
static int alloc_pool(int bi, int idx, int num, unsigned long long reqsize,
		      phys_addr_t *physpRet)
{
	struct pool_buffer *entry;
	struct list_head *freelistp = &p_objs[bi][idx].freelist;
	struct list_head *busylistp = &p_objs[bi][idx].busylist;
	unsigned long long size = PAGE_ALIGN(reqsize);
	phys_addr_t physp;
	int i;

	__D("Allocating %d buffers of size 0x%llx (requested 0x%llx)\n",
	    num, size, reqsize);

	p_objs[bi][idx].reqsize = reqsize;
	p_objs[bi][idx].numbufs = num;
	p_objs[bi][idx].size = size;

	INIT_LIST_HEAD(freelistp);
	INIT_LIST_HEAD(busylistp);

	for (i = 0; i < num; i++) {
		entry = kmalloc(sizeof(struct pool_buffer), GFP_KERNEL);

		if (!entry) {
			__E("alloc_pool failed to malloc pool_buffer struct");
			return -ENOMEM;
		}

		physp = alloc_pool_buffer(bi, size);

		if (physp == 0) {
			__E("alloc_pool failed to get contiguous area of size %llu\n",
			    size);

			/*
			 * Need to free this entry now since it didn't get added to
			 * a list that will be freed during module removal (cmem_exit())
			 * Fixes SDSCM00027040.
			 */
			kfree(entry);

			return -ENOMEM;
		}

		entry->id = i;
		entry->physp = physp;
		entry->size = size;
		entry->kvirtp = NULL;
		entry->vma = NULL;
		INIT_LIST_HEAD(&entry->users);

		if (physpRet) {
			*physpRet++ = physp;
		}

		__D("Allocated buffer %d, physical %#llx and size %#llx\n",
			entry->id, (unsigned long long)entry->physp, size);

		list_add_tail(&entry->element, freelistp);
	}

#ifdef __DEBUG
	dump_lists(bi, idx);
#endif

	return 0;
}

static int mmap_buffer(struct pool_buffer *entry, struct vm_area_struct *vma,
	unsigned long size)
{

	if (size > entry->size) {
		__E("mmap_buffer: requested size %#llx too big (should be <= %#llx)\n",
		    (unsigned long long)size, (unsigned long long)entry->size);

		return -EINVAL;
	}

	if (entry->flags & CMEM_CACHED) {
#ifndef DISABLE_CACHE_OPERATIONS
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
			(L_PTE_MT_WRITEALLOC | L_PTE_MT_BUFFERABLE));
#endif
	}
	else {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	}
	vma->vm_flags |= VM_RESERVED | VM_IO;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
			    vma->vm_page_prot)) {
		__E("mmap_buffer: failed remap_pfn_range\n");

		return -EAGAIN;
	}
	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))

static int cmem_dmabuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct pool_buffer *entry = dmabuf->priv;
	unsigned long size = vma->vm_end - vma->vm_start;

	__D("cmem_dmabuf_mmap: vma->vm_start     = %#lx\n", vma->vm_start);
	__D("cmem_dmabuf_mmap: vma->vm_end       = %#lx\n", vma->vm_end);
	__D("cmem_dmabuf_mmap: size              = %#lx\n", size);
	__D("cmem_dmabuf_mmap: vma->vm_pgoff     = %#lx\n", vma->vm_pgoff);

	if (entry == NULL)
		return -EAGAIN;

	/* Use the physical address from buffer to map */
	vma->vm_pgoff = entry->physp >> PAGE_SHIFT;

	return mmap_buffer(entry, vma, size);
}

/**
 * cmem_dmabuf_release - dma_buf release implementation
 * @dma_buf: buffer to be released
 *
 */
static void cmem_dma_buf_release(struct dma_buf *dma_buf)
{
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
static void *cmem_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct pool_buffer *entry = dmabuf->priv;

	if ( entry->kvirtp )
		return entry->kvirtp + offset * PAGE_SIZE;
	else
		return NULL;
}

static void cmem_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
			       void *ptr)
{
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0))
static int cmem_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				       enum dma_data_direction direction)
#else
static void cmem_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction)

#endif
{
#ifndef DISABLE_CACHE_OPERATIONS
	struct pool_buffer *entry = dmabuf->priv;

	if ( entry->kvirtp )
		dmac_map_area(entry->kvirtp, entry->size, direction);
	/* TODO: Need to take care of case where kvirtp is not set */

	outer_clean_range(entry->physp, entry->physp + entry->size);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0))
	return 0;
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0))
static int cmem_dmabuf_map_attach(struct dma_buf *dma_buf,
			      struct device *target_dev,
			      struct dma_buf_attachment *attach)
#else
static int cmem_dmabuf_map_attach(struct dma_buf *dma_buf,
			      struct dma_buf_attachment *attach)
#endif
{
	struct cmem_dmabuf_attachment *cmem_dmabuf_attach;

	cmem_dmabuf_attach = kzalloc(sizeof(*cmem_dmabuf_attach), GFP_KERNEL);
	if (!cmem_dmabuf_attach) {
		__E("cmem_dmabuf_map_attach:kzalloc failed\n");
		return -ENOMEM;
	}

	cmem_dmabuf_attach->dir = DMA_NONE;
	attach->priv = cmem_dmabuf_attach;

	return 0;
}

static struct sg_table *cmem_map_dma_buf(struct dma_buf_attachment *attach,
					 enum dma_data_direction dir)
{
	struct cmem_dmabuf_attachment *cmem_dmabuf_attach = attach->priv;
	struct dma_buf *dmabuf = attach->dmabuf;
	struct pool_buffer *entry = dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	if (WARN_ON(dir == DMA_NONE || !cmem_dmabuf_attach)) {
		__E("cmem_map_dma_buf: Invalid dir or no attach\n");
		return ERR_PTR(-EINVAL);
	}

	/* return the cached mapping when possible */
	if (cmem_dmabuf_attach->dir == dir)
		return cmem_dmabuf_attach->sgt;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);

	if (!sgt) {
		__E("cmem_map_dma_buf: kzalloc failed\n");
		return ERR_PTR(-ENOMEM);
	}
	ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (ret)
		goto out;

	sg_init_table(sgt->sgl, 1);
	sg_dma_len(sgt->sgl) = entry->size;
	sg_set_page(sgt->sgl, pfn_to_page(PFN_DOWN(entry->physp)),
		    entry->size, 0);
	sg_dma_address(sgt->sgl) = entry->physp;

	/* dma sync buffer */
	cmem_dma_buf_end_cpu_access(dmabuf, dir);
	cmem_dmabuf_attach->sgt = sgt;
	cmem_dmabuf_attach->dir = dir;

	return cmem_dmabuf_attach->sgt;

out:
	kfree(sgt);
	cmem_dmabuf_attach->sgt = NULL;
	cmem_dmabuf_attach->dir = DMA_NONE;
	return ERR_PTR(ret);
}

static void cmem_unmap_dma_buf(struct dma_buf_attachment *attach,
			      struct sg_table *table,
			      enum dma_data_direction direction)
{
	struct cmem_dmabuf_attachment *cmem_dmabuf_attach = attach->priv;

	sg_free_table(cmem_dmabuf_attach->sgt);
	kfree(cmem_dmabuf_attach->sgt);
	cmem_dmabuf_attach->sgt = NULL;
	cmem_dmabuf_attach->dir = DMA_NONE;
}

static int cmem_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					 enum dma_data_direction direction)
{
#ifndef DISABLE_CACHE_OPERATIONS
	struct pool_buffer *entry = dmabuf->priv;

	outer_inv_range(entry->physp, entry->physp + entry->size);
	if ( entry->kvirtp )
		dmac_map_area(entry->kvirtp, entry->size, direction);

	/* TODO: Need to take care of case where kvirtp is not set */
#endif
	return 0;
}

static void cmem_dmabuf_map_detach(struct dma_buf *dma_buf,
			       struct dma_buf_attachment *attach)
{
	struct  cmem_dmabuf_attachment * cmem_dmabuf_attach = attach->priv;
	struct sg_table *sgt;

	if (!cmem_dmabuf_attach)
		return;

	sgt = cmem_dmabuf_attach->sgt;
	if (sgt) {
		if (cmem_dmabuf_attach->dir != DMA_NONE)
			dma_unmap_sg(attach->dev, sgt->sgl, sgt->nents,
					cmem_dmabuf_attach->dir);
		sg_free_table(sgt);
	}

	kfree(sgt);
	kfree(cmem_dmabuf_attach);
	attach->priv = NULL;
}

static const struct dma_buf_ops cmem_dmabuf_ops =  {
	.attach = cmem_dmabuf_map_attach,
	.detach = cmem_dmabuf_map_detach,
	.map_dma_buf = cmem_map_dma_buf,
	.unmap_dma_buf = cmem_unmap_dma_buf,
	.mmap = cmem_dmabuf_mmap,
	.release = cmem_dma_buf_release,
	.begin_cpu_access = cmem_dma_buf_begin_cpu_access,
	.end_cpu_access = cmem_dma_buf_end_cpu_access,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0))
	.kmap_atomic = cmem_dma_buf_kmap,
	.kunmap_atomic = cmem_dma_buf_kunmap,
	.kmap = cmem_dma_buf_kmap,
	.kunmap = cmem_dma_buf_kunmap,
#else
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0))
	.map_atomic = cmem_dma_buf_kmap,
	.unmap_atomic = cmem_dma_buf_kunmap,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
	.map = cmem_dma_buf_kmap,
	.unmap = cmem_dma_buf_kunmap,
#endif
#endif
};

static void *map_virt_addr(phys_addr_t physp, unsigned long long size)
{
	void *vaddr;

	vaddr = ioremap((resource_size_t)physp, size);
	if (vaddr == NULL) {
		__E("%s: ioremap(%#llx, %#llx) failed\n",
		    __func__,
		    (unsigned long long)physp,
		    (unsigned long long)size);
		return NULL;
	}

	__D("map_virt_addr: ioremap(%#llx, %#llx)=0x%p\n",
		(unsigned long long)physp, (unsigned long long)size, vaddr);

	return vaddr;
}
#endif

/**
 * cmem_dmabuf_export - helper library implementation of the export callback
 * @dev: cmem_device to export from
 * @obj:  object to export
 * @flags: 
 *
 * This is the implementation of the cmem_dmabuf_export functions for CMEM
 */
struct dma_buf *cmem_dmabuf_export(struct pool_buffer *entry, int flags)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	if(entry->kvirtp == NULL) {
		/* Map kernel virt memory */
		entry->kvirtp = map_virt_addr(entry->physp, entry->size);	
		if ( entry->kvirtp == NULL ) {
			__E("cmem_dmabuf_export:map_virt_addr failed\n");
			return ERR_PTR(-EINVAL);
		}
	}

	exp_info.ops = &cmem_dmabuf_ops;
	exp_info.size = entry->size;
	exp_info.flags = flags;
	exp_info.priv = entry;

	return dma_buf_export(&exp_info);
#else
	/* dmabuf export not supported */
	return ERR_PTR(-EINVAL);
#endif
}
EXPORT_SYMBOL(cmem_dmabuf_export);

static long ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	unsigned int __user *argp = (unsigned int __user *) args;
	unsigned long __user *largp = (unsigned long __user *) args;
	unsigned long long __user *llargp = (unsigned long long __user *) args;
	unsigned long virtArg;
	unsigned long long physArg;
	struct list_head *freelistp = NULL;
	struct list_head *busylistp = NULL;
	struct list_head *registeredlistp;
	struct list_head *e = NULL;
	struct list_head *u;
	struct list_head *unext;
	struct pool_buffer *entry;
	struct registered_user *user;
	phys_addr_t physp;
	void *virtp;
	void *virtp_end;
	dma_addr_t dma = 0;
	size_t reqsize, align;
	size_t size = 0;
	unsigned long long lsize, lreqsize;
	unsigned long long delta = MAXTYPE(unsigned long long);
	int pool = -1;
	int i;
	int bi;
	int id;
	int pool_alloc;
	struct CMEM_block_struct block;
	union CMEM_AllocUnion allocDesc;
	struct device *dev = NULL;
	struct dma_buf *dmabuf;
	int ret;

	if (_IOC_TYPE(cmd) != _IOC_TYPE(CMEM_IOCMAGIC)) {
		__E("ioctl(): bad command type %#x (should be %#x)\n",
		    _IOC_TYPE(cmd), _IOC_TYPE(CMEM_IOCMAGIC));
	}

	switch (cmd & CMEM_IOCCMDMASK) {
	case CMEM_IOCALLOCHEAP:
		if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
			return -EFAULT;
		}

		size = allocDesc.alloc_heap_inparams.size;
		align = allocDesc.alloc_heap_inparams.align;
		bi = allocDesc.alloc_heap_inparams.blockid;

		if (bi == CMEM_CMABLOCKID) {
			bi = NBLOCKS;

			if (cmem_cma_heapsize == 0) {
				__D("no explicit CMEM CMA heap, using global area\n");
				dev = cmem_cma_dev_0;
			}
			else {
				dev = &cmem_cma_dev[heap_pool[bi]];
			}
		}

		__D("ALLOCHEAP%s ioctl received on heap pool for block %d\n",
		cmd & CMEM_CACHED ? "CACHED" : "", bi);

		if (bi > NBLOCKS || bi < 0) {
			__E("ioctl: invalid block id %d, must be < %d\n",
			    bi, NBLOCKS);
			return -EINVAL;
		}

		/* heap_pool[NBLOCKS] (the CMA heap) is always available */
		if (bi < NBLOCKS && heap_pool[bi] == -1) {
			__E("ioctl: no heap available in block %d\n", bi);
			return -EINVAL;
		}

		pool = heap_pool[bi];

		pool_alloc = 0;
alloc:
		entry = kmalloc(sizeof(struct pool_buffer), GFP_KERNEL);
		if (!entry) {
			__E("ioctl: failed to kmalloc pool_buffer struct for heap");

			return -ENOMEM;
		}

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}

		size = PAGE_ALIGN(size);

		if (bi == NBLOCKS) {
			virtp = dma_alloc_coherent(dev, size, &dma, GFP_KERNEL);

#if IS_ENABLED(CONFIG_ARCH_KEYSTONE) && IS_ENABLED(CONFIG_ARM_LPAE) \
	&& (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
			/* adjust from 32-bit alias to 36-bit phys */
			physp = dma
				+ ((unsigned long long)KEYSTONE_DMA_PFN_OFFSET
				   << PAGE_SHIFT);
#else
			physp = dma;
#endif
			entry->dev = dev;
			entry->kvirtp = virtp;
		}
		else {
			physp = HeapMem_alloc(bi, size, align, ALLOCRUN);
			entry->kvirtp = NULL;
			/* set only for test just below here */
			virtp = (void *)(uintptr_t)physp;
		}

		if (virtp == NULL) {
			__E(
			    "ioctl: failed to allocate from block %d: heap buffer of size %zx\n",
			    bi, size);

			mutex_unlock(&cmem_mutex);
			kfree(entry);

			return -ENOMEM;
		}

		entry->dma = dma;
		entry->id = pool;
		entry->physp = physp;
		entry->size = size;
		entry->flags = cmd & ~CMEM_IOCCMDMASK;
		entry->vma = NULL;
		INIT_LIST_HEAD(&entry->users);

		busylistp = &p_objs[bi][pool].busylist;
		list_add_tail(&entry->element, busylistp);

		user = kmalloc(sizeof(struct registered_user), GFP_KERNEL);
		user->filp = filp;
		list_add(&user->element, &entry->users);

		mutex_unlock(&cmem_mutex);

		if (pool_alloc) {
			allocDesc.alloc_pool_outparams.physp = physp;
			allocDesc.alloc_pool_outparams.size = size;

			if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
				return -EFAULT;
			}
		}
		else {
			if (put_user((unsigned long long)physp, llargp)) {
				return -EFAULT;
			}
		}

		__D("ALLOCHEAP%s: allocated %#zx size buffer at %llx (phys address)\n",
		    cmd & CMEM_CACHED ? "CACHED" : "", (size_t)entry->size,
		    (unsigned long long)entry->physp);

		break;

		/*
		 * argp contains a pointer to an alloc descriptor coming in, and the
		 * physical address and size of the allocated buffer when returning.
		 */
		case CMEM_IOCALLOC:
		if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
			return -EFAULT;
		}

		pool = allocDesc.alloc_pool_inparams.poolid;
		bi = allocDesc.alloc_pool_inparams.blockid;

		if (bi == CMEM_CMABLOCKID) {
			bi = NBLOCKS;
		}

		__D("ALLOC%s ioctl received on pool %d for memory block %d\n",
		    cmd & CMEM_CACHED ? "CACHED" : "", pool, bi);

		if (bi > NBLOCKS || bi < 0) {
			__E("ioctl: invalid block id %d, must be < %d\n",
			    bi, NBLOCKS);
			return -EINVAL;
		}

		if (pool >= npools[bi] || pool < 0) {
			__E("ALLOC%s: invalid pool (%d) passed.\n",
			    cmd & CMEM_CACHED ? "CACHED" : "", pool);
			return -EINVAL;
		}

		if (bi == NBLOCKS) {
			lsize = p_objs[bi][pool].size;
			dev = &cmem_cma_dev[pool];
				align = 0;
				pool_alloc = 1;

			goto alloc;
		}

		busylistp = &p_objs[bi][pool].busylist;
		freelistp = &p_objs[bi][pool].freelist;

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}

		e = freelistp->next;
		if (e == freelistp) {
			__E("ALLOC%s: No free buffers available for pool %d\n",
			    cmd & CMEM_CACHED ? "CACHED" : "", pool);
			mutex_unlock(&cmem_mutex);
			return -ENOMEM;
		}
		entry = list_entry(e, struct pool_buffer, element);

		allocDesc.alloc_pool_outparams.physp = entry->physp;
		allocDesc.alloc_pool_outparams.size = p_objs[bi][pool].size;

		if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
			mutex_unlock(&cmem_mutex);
			return -EFAULT;
		}

		entry->flags = cmd & ~CMEM_IOCCMDMASK;

		list_del_init(e);
		list_add(e, busylistp);

		user = kmalloc(sizeof(struct registered_user), GFP_KERNEL);
		user->filp = filp;
		list_add(&user->element, &entry->users);

		mutex_unlock(&cmem_mutex);

		__D("ALLOC%s: allocated a buffer at %#llx (phys address)\n",
		    cmd & CMEM_CACHED ? "CACHED" : "",
		    (unsigned long long)entry->physp);

#ifdef __DEBUG
		dump_lists(bi, pool);
#endif
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
			if (get_user(virtArg, largp)) {
				return -EFAULT;
			}

			physp = get_phys((void *)virtArg);

			if (physp == ~(0LL)) {
				__E("FREE%s: Failed to convert virtual %#lx to physical\n",
				    cmd & CMEM_HEAP ? "HEAP" : "", virtArg);
				return -EFAULT;
			}

			virtp = (void *)virtArg;

			__D("FREE%s: translated 0x%p user virtual to %#llx physical\n",
			    cmd & CMEM_HEAP ? "HEAP" : "",
			    virtp, (unsigned long long)physp);
		} else {
				virtp = 0L;	/* silence the compiler warning */
				if (copy_from_user(&physArg, llargp,
				    sizeof(unsigned long long))) {
				return -EFAULT;
			}
			physp = physArg;
		}

		if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
		}

		size = 0;

		entry = find_busy_entry(physp, &pool, &e, &bi, NULL);
		if (entry) {
			/* record values in case entry gets kfree()'d for CMEM_HEAP */
			id = entry->id;
			size = (size_t)entry->size;

			registeredlistp = &entry->users;
			u = registeredlistp->next;
			while (u != registeredlistp) {
				unext = u->next;

				user = list_entry(u, struct registered_user, element);
				if (user->filp == filp) {
					__D("FREE%s%s: Removing file 0x%p from user list of buffer %#llx...\n",
					    cmd & CMEM_HEAP ? "HEAP" : "",
					    cmd & CMEM_PHYS ? "PHYS" : "",
					    filp, (unsigned long long)physp);

					list_del(u);
					kfree(user);

					break;
				}

				u = unext;
			}

			if (u == registeredlistp) {
				__E("FREE%s%s: Not a registered user of physical buffer %#llx\n",
				    cmd & CMEM_HEAP ? "HEAP" : "",
				    cmd & CMEM_PHYS ? "PHYS" : "",
				    (unsigned long long)physp);
				mutex_unlock(&cmem_mutex);

				return -EFAULT;
			}

			if (registeredlistp->next == registeredlistp) {
				/* no more registered users, free buffer */
				if (bi == NBLOCKS || pool == heap_pool[bi]) {
					if (!(cmd & CMEM_PHYS) && bi != NBLOCKS) {
						/*
						 * Need to invalidate possible cached entry for
						 * user's virt addr since the kernel is about to
						 * do a non-cached write to the entry in
						 * HeapMem_free()
						 */
						virtp_end = virtp + size;
#ifndef DISABLE_CACHE_OPERATIONS
						outer_inv_range(physp, physp + size);
						dmac_map_area(virtp, size, DMA_FROM_DEVICE);
						__D("FREEHEAP: invalidated user virtual "
						    "0x%p -> 0x%p\n", virtp, virtp_end);
#endif
					}

					if (bi == NBLOCKS) {
						dma_free_coherent(entry->dev, (size_t)entry->size,
							  	  entry->kvirtp, entry->dma);
					}
					else {
						/* Free any kernel virtual address mapping for exported buffers */
						if(entry->kvirtp) {
							iounmap(entry->kvirtp);
							entry->kvirtp = NULL;
						}
						HeapMem_free(bi, entry->physp, (size_t)entry->size);
						if (entry->vma) {
							free_vm_area(entry->vma);
						}
					}
					list_del(e);
					kfree(entry);
				}
				else {
					list_del_init(e);
					list_add(e, &p_objs[bi][pool].freelist);
				}

				__D("FREE%s%s: Successfully freed buffer %d from pool %d\n",
				    cmd & CMEM_HEAP ? "HEAP" : "",
				    cmd & CMEM_PHYS ? "PHYS" : "", id, pool);
			}
		}

		mutex_unlock(&cmem_mutex);

		if (!entry) {
			__E("Failed to free memory at %#llx\n",
			    (unsigned long long)physp);
			return -EFAULT;
		}

#ifdef __DEBUG
		dump_lists(bi, pool);
#endif
		if (cmd & CMEM_PHYS) {
			__D("FREE%sPHYS: returning\n", cmd & CMEM_HEAP ? "HEAP" : "");
		}
		else {
			if (pool == heap_pool[bi]) {
				allocDesc.free_outparams.size = size;
			}
			else {
				allocDesc.free_outparams.size = p_objs[bi][pool].size;
			}
			allocDesc.free_outparams.poolid = pool;
				if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
				return -EFAULT;
			}

			__D("FREE%s%s: returning size 0x%zx, poolid %d\n",
			    cmd & CMEM_HEAP ? "HEAP" : "",
			    cmd & CMEM_PHYS ? "PHYS" : "",
			    allocDesc.free_outparams.size,
			    allocDesc.free_outparams.poolid);
		}

		break;

	/*
	 * argp contains the user virtual address of the buffer to translate
	 * coming in, and the translated physical address on return.
	 */
	case CMEM_IOCGETPHYS:
		__D("GETPHYS ioctl received.\n");
		if (get_user(virtArg, largp)) {
			return -EFAULT;
		}

		physp = get_phys((void *)virtArg);

		if (physp == ~(0LL)) {
			__E("GETPHYS: Failed to convert virtual %#lx to physical.\n",
			    virtArg);
			return -EFAULT;
		}

		if (put_user(physp, llargp)) {
			return -EFAULT;
		}

		__D("GETPHYS: returning %#llx\n", (unsigned long long)physp);
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
		bi = allocDesc.get_size_inparams.blockid;

		if (bi == CMEM_CMABLOCKID) {
		bi = NBLOCKS;
		}

		if (bi > NBLOCKS || bi < 0) {
			__E("ioctl: invalid block id %d, must be < %d\n",
			    bi, NBLOCKS);
			return -EINVAL;
		}

		if (pool >= npools[bi] || pool < 0) {
			__E("GETSIZE: invalid pool (%d) passed.\n", pool);
			return -EINVAL;
		}

		if (put_user(p_objs[bi][pool].size, argp)) {
			return -EFAULT;
		}
		__D("GETSIZE returning %#llx\n", p_objs[bi][pool].size);
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

		lreqsize = allocDesc.get_pool_inparams.size;
		bi = allocDesc.get_pool_inparams.blockid;

		if (bi == CMEM_CMABLOCKID) {
			bi = NBLOCKS;
		}

		if (bi > NBLOCKS || bi < 0) {
			__E("ioctl: invalid block id %d, must be < %d\n",
			    bi, NBLOCKS);
			return -EINVAL;
		}

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}

		__D("GETPOOL: Trying to find a pool to fit size %#llx\n", lreqsize);
		for (i = 0; i < npools[bi]; i++) {
			lsize = p_objs[bi][i].size;
			freelistp = &p_objs[bi][i].freelist;

			__D("GETPOOL: size (%#llx) > reqsize (%#llx)?\n",
			    lsize, lreqsize);
			if (lsize >= lreqsize) {
				__D("GETPOOL: delta (%#llx) < olddelta (%#llx)?\n",
				    lsize - lreqsize, delta);
				if ((lsize - lreqsize) < delta) {
					if (bi < NBLOCKS) {
						if (!list_empty(freelistp)) {
							delta = lsize - lreqsize;
							pool = i;
							__D("GETPOOL: Found a best fit delta %#llx in pool %d\n",
							    delta, pool);
						}
					}
					else {
						delta = lsize - lreqsize;
						pool = i;
						__D("GETPOOL: Found a best fit delta %#llx in CMA block\n",
						    delta);
					}
				}
			}
		}

		if (pool == -1 && heap_pool[bi] != -1) {
			if (useHeapIfPoolUnavailable) {
				/* no pool buffer available, try heap */

				reqsize = lreqsize;
				physp = HeapMem_alloc(bi, reqsize, HEAP_ALIGN, DRYRUN);
				if (physp != 0) {
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
		}

		mutex_unlock(&cmem_mutex);

		if (pool == -1) {
			__E("Failed to find a pool which fits %#llx\n", lreqsize);

			return -ENOMEM;
		}

		if (put_user(pool, argp)) {
			return -EFAULT;
		}
		__D("GETPOOL: returning %d\n", pool);
		break;

	case CMEM_IOCCACHEWBINVALL:
#ifndef DISABLE_CACHE_OPERATIONS
		flush_cache_all();
		__D("CACHEWBINVALL: flush all cache\n");
#endif
		break;

	case CMEM_IOCCACHE:
		__D("CACHE%s%s ioctl received.\n",
		    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "");

		if (copy_from_user(&block, argp, sizeof(block))) {
			return -EFAULT;
		}
		virtp = block.addr;
		virtp_end = virtp + block.size;

#ifdef CHECK_FOR_ALLOCATED_BUFFER
		physp = get_phys(virtp);
		if (physp == ~(0LL)) {
			__E("CACHE%s%s: Failed to convert virtual 0x%p to physical\n",
			    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "",
			    virtp);
			return -EFAULT;
		}

		__D("CACHE%s%s: translated 0x%p user virtual to %#lx physical\n",
		    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "",
		    virtp, physp);

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}
		entry = find_busy_entry(physp, &pool, &e, &bi, &block.size);
		mutex_unlock(&cmem_mutex);
		if (!entry) {
			__E("CACHE%s%s: Failed to find allocated buffer at virtual 0x%p\n",
			    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "",
			    virtp);
			return -ENXIO;
		}
		if (!(entry->flags & CMEM_CACHED)) {
			__E("CACHE%s%s: virtual buffer 0x%p not cached\n",
			    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "",
			    virtp);
			return -EINVAL;
		}
#endif

#ifdef USE_MMAPSEM
		__D("CACHE%s%s: acquiring mmap_sem ...\n",
		    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "");
		down_write(&current->mm->mmap_sem);
#endif

		physp = get_phys(virtp);

		switch (cmd & ~CMEM_IOCMAGIC) {
		case CMEM_IOCCACHEWB:
#ifndef DISABLE_CACHE_OPERATIONS
			dmac_map_area(virtp, block.size, DMA_TO_DEVICE);
			outer_clean_range(physp, physp + block.size);

			__D("CACHEWB: cleaned user virtual 0x%p -> 0x%p\n",
			    virtp, virtp_end);
#endif

			break;

		case CMEM_IOCCACHEINV:
#ifndef DISABLE_CACHE_OPERATIONS
			outer_inv_range(physp, physp + block.size);
			dmac_map_area(virtp, block.size, DMA_FROM_DEVICE);

			__D("CACHEINV: invalidated user virtual 0x%p -> 0x%p\n",
			    virtp, virtp_end);
#endif
			break;

		case CMEM_IOCCACHEWBINV:
#ifndef DISABLE_CACHE_OPERATIONS
			dmac_map_area(virtp, block.size, DMA_BIDIRECTIONAL);
			outer_flush_range(physp, physp + block.size);

			__D("CACHEWBINV: flushed user virtual 0x%p -> 0x%p\n",
			    virtp, virtp_end);
#endif

			break;
		}

#ifdef USE_MMAPSEM
		__D("CACHE%s%s: releasing mmap_sem ...\n",
		    cmd & CMEM_WB ? "WB" : "", cmd & CMEM_INV ? "INV" : "");
		up_write(&current->mm->mmap_sem);
#endif

		break;

	case CMEM_IOCGETVERSION:
		__D("GETVERSION ioctl received, returning %#x.\n", version);

		if (put_user(version, argp)) {
			return -EFAULT;
		}

		break;

	case CMEM_IOCGETBLOCK:
		__D("GETBLOCK ioctl received.\n");

		if (copy_from_user(&allocDesc, argp, sizeof(allocDesc))) {
			return -EFAULT;
		}

		bi = allocDesc.blockid;
		if (bi >= nblocks || bi < 0) {
			__E("GETBLOCK: invalid block ID %d\n", bi);

			return -EINVAL;
		}

		allocDesc.get_block_outparams.physp = block_start[bi];
		allocDesc.get_block_outparams.size = block_end[bi] -
						     block_start[bi];

		__D("GETBLOCK: returning phys base "
		    "%#llx, size %#llx.\n", allocDesc.get_block_outparams.physp,
		    allocDesc.get_block_outparams.size);

		if (copy_to_user(argp, &allocDesc, sizeof(allocDesc))) {
			return -EFAULT;
		}

		break;

	case CMEM_IOCGETNUMBLOCKS:
		__D("GETNUMBLOCKS ioctl received, returning %d.\n", nblocks);

		if (put_user(nblocks, argp)) {
			return -EFAULT;
		}

		break;

	case CMEM_IOCREGUSER:
		__D("REGUSER ioctl received.\n");

		if (copy_from_user(&physArg, llargp, sizeof(unsigned long long))) {
			return -EFAULT;
		}
		physp = physArg;

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}

		entry = find_busy_entry(physp, &pool, &e, &bi, NULL);
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

	case CMEM_IOCEXPORTDMABUF:
	{
		struct CMEM_dmabufDesc dmabuf_desc;

		__D("EXPORTDMABUF ioctl received.\n");

		if (copy_from_user(&dmabuf_desc, argp, sizeof(dmabuf_desc))) {
			return -EFAULT;
		}

		/* Get the physical address */
		physp = get_phys((void *)dmabuf_desc.virtp);

		if (physp == ~(0LL)) {
			__E("GETPHYS: Failed to convert virtual %p to physical.\n",
			    (void *)dmabuf_desc.virtp);
			return -EFAULT;
		}

		if (mutex_lock_interruptible(&cmem_mutex)) {
			return -ERESTARTSYS;
		}

		/* Lookup physp in the busy entry list */
		entry = find_busy_entry(physp, &pool, &e, &bi, NULL);

		if (entry == NULL) {
			__E(" Failed to find entry virtp: %p physp: %#llx \n",
			    (void *)dmabuf_desc.virtp, (unsigned long long)physp);
			mutex_unlock(&cmem_mutex);
			return -EFAULT;
		}

		/* Export to dmabuf */
		dmabuf = cmem_dmabuf_export(entry, O_RDWR);
		if (IS_ERR(dmabuf)) {
			/* normally the created dma-buf takes ownership of the ref,
			 * but if that fails then drop the ref
			 */
			ret = PTR_ERR(dmabuf);
			mutex_unlock(&cmem_mutex);
			return -EFAULT;
		}

		/* Get the fd for dmabuf */
		ret = dma_buf_fd(dmabuf, O_CLOEXEC);
		if (ret < 0) {
			dma_buf_put(dmabuf);
			mutex_unlock(&cmem_mutex);
			return -EFAULT;
		}

		/* return the dmafd */
		dmabuf_desc.fd_dmabuf = ret;
		if (copy_to_user(argp, &dmabuf_desc, sizeof(dmabuf_desc))) {
			 mutex_unlock(&cmem_mutex);
			return -EFAULT;
		}
		mutex_unlock(&cmem_mutex);
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
	phys_addr_t physp;
	struct pool_buffer *entry;
	unsigned long size = vma->vm_end - vma->vm_start;
	size_t s;

	__D("mmap: vma->vm_start     = %#lx\n", vma->vm_start);
	__D("mmap: vma->vm_end       = %#lx\n", vma->vm_end);
	__D("mmap: size              = %#lx\n", size);
	__D("mmap: vma->vm_pgoff     = %#lx\n", vma->vm_pgoff);

	physp = (unsigned long long)vma->vm_pgoff << PAGE_SHIFT;

	if (mutex_lock_interruptible(&cmem_mutex)) {
		return -ERESTARTSYS;
	}

	s = size;
	entry = find_busy_entry(physp, NULL, NULL, NULL, &s);
	mutex_unlock(&cmem_mutex);

	if (entry != NULL) {
		return mmap_buffer(entry, vma, size);
	}
	else {
		__E("mmap: can't find allocated buffer with physp %#llx\n",
		    (unsigned long long)physp);

		return -EINVAL;
	}
}

static int open(struct inode *inode, struct file *filp)
{
	__D("open: called.\n");

	atomic_inc(&reference_count);
	filp->f_mode |= FMODE_UNSIGNED_OFFSET;

	return 0;
}

static int release(struct inode *inode, struct file *filp)
{
	struct list_head *registeredlistp;
	struct list_head *freelistp;
	struct list_head *busylistp;
	struct list_head *e;
	struct list_head *u;
	struct list_head *next;
	struct list_head *unext;
	struct pool_buffer *entry;
	struct registered_user *user;
	int last_close = 0;
	int num_pools;
	int bi;
	int i;

	__D("close: called.\n");

	/* Force free all buffers owned by the 'current' process */

	if (atomic_dec_and_test(&reference_count)) {
		__D("close: all references closed, force freeing all busy buffers.\n");

		last_close = 1;
	}

	for (bi = 0; bi < (NBLOCKS + 1); bi++) {
		num_pools = npools[bi];
		if (heap_pool[bi] != -1) {
			num_pools++;
		}

		/* Clean up any buffers on the busy list when cmem is closed */
		for (i = 0; i < num_pools; i++) {
			__D("Forcing free on pool %d\n", i);

			/* acquire the mutex in case this isn't the last close */
			if (mutex_lock_interruptible(&cmem_mutex)) {
				return -ERESTARTSYS;
			}

			freelistp = &p_objs[bi][i].freelist;
			busylistp = &p_objs[bi][i].busylist;

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
						__D("Removing file 0x%p from user list of buffer %#llx...\n",
						    user->filp, (unsigned long long)entry->physp);

						list_del(u);
						kfree(user);
					}

					u = unext;
				}

				if (registeredlistp->next == registeredlistp) {
					/* no more registered users, free buffer */

					if ((heap_pool[bi] != -1) && (i == (num_pools - 1))) {
						/* HEAP */
						__D("Warning: Freeing 'busy' buffer from heap at "
						    "%#llx\n", (unsigned long long)entry->physp);

						if (bi == NBLOCKS) {
							dma_free_coherent(NULL, entry->size,
							entry->kvirtp, entry->dma);
						}
						else {
							/* Free any kernel virtual address mapping for exported buffers */
							if(entry->kvirtp) {
								iounmap(entry->kvirtp);
								entry->kvirtp = NULL;
							}

							HeapMem_free(bi, entry->physp, entry->size);
						}
						list_del(e);
						kfree(entry);
					} else {
						/* POOL */
						__D("Warning: Putting 'busy' buffer from pool %d at "
						    "%#llx on freelist\n",
						    i, (unsigned long long)entry->physp);

						list_del_init(e);
						list_add(e, freelistp);
					}
				}

				e = next;
			}

			mutex_unlock(&cmem_mutex);
		}
	}

	__D("close: returning\n");

	return 0;
}

static void banner(void)
{
	printk(KERN_INFO "CMEMK module: reference Linux version %d.%d.%d\n",
	       (LINUX_VERSION_CODE & 0x00ff0000) >> 16,
	       (LINUX_VERSION_CODE & 0x0000ff00) >> 8,
	       (LINUX_VERSION_CODE & 0x000000ff) >> 0
	      );
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)

/*
 * dt_config needs to set:
 *   block_start[bi]
 *   block_end[bi]
 *   npools[bi]
 *   pool_num_buffers[bi][p]
 *   pool_size[bi][p]
 * for blocks specified in DT
 */
int dt_config(void)
{
	struct device_node *np, *block, *mem;
	int ret;
	u32 tmp[MAX_POOLS * 3];
	unsigned long long addr;
	unsigned long long size;
	int n, p;
	int i;
	int num_pools;
	u32 num_buffers;
	u32 pool_size_cells;
	int ints_per_pool;
	unsigned long long buffer_size;
	int block_num;
	struct resource temp_res;

	np = of_find_compatible_node(NULL, NULL, "ti,cmem");
	if (!np) {
		__D("no cmem node found in device tree\n");
		return -ENODEV;
	}

	__D("found cmem node in device tree, getting child nodes\n");

	if (of_get_available_child_count(np) == 0) {
		__E("no child block node(s) found\n");
		return -EINVAL;
	}

	pool_size_cells = 1;
	if (of_get_property(np, "#pool-size-cells", NULL) != NULL) {
		of_property_read_u32(np, "#pool-size-cells", &pool_size_cells);
	}
	ints_per_pool = pool_size_cells + 1;

	block = NULL;

	while ((block = of_get_next_available_child(np, block)) != NULL) {
		__D("got child\n");

		if (of_property_read_u32(block, "reg", &block_num)) {
			__E("cmem block has no reg property\n");
			return -EINVAL;
		}
		if (block_num < 0 || block_num >= NBLOCKS) {
			__E("cmem block 'address' (reg property) %d out of range\n"
			    "  must be 0 -> %d\n", block_num, NBLOCKS - 1);
			return -EINVAL;
		}
		if (block_start[block_num] != 0) {
			__E("cmem block %d already assigned\n", block_num);
			return -EINVAL;
		}

		/* Set default type to reserved memory node */
		block_type[block_num] = BLOCK_TYPE_RESV_MEMORY_NODE;

		__D("  looking for memory-region phandle\n");

		mem = of_parse_phandle(block, "memory-region", 0);
		if (!mem) {
			/* Look for sram phandle */
			mem = of_parse_phandle(block, "sram", 0);
			if (!mem) {
				__E("no memory-region phandle\n");
				return -EINVAL;
			}
			block_type[block_num] = BLOCK_TYPE_SRAM_NODE;
		}

		__D("got memory-region\n");

		if (!of_device_is_available(mem)) {
			__E("Error sub device node not available\n");
			return -EINVAL;
		}

		__D("got device for memory: block type %d\n",
		    block_type[block_num]);

		ret = of_address_to_resource(mem, 0, &temp_res);
		if (ret) {
			__E("Could not get resource %d\n", ret);
			return -EINVAL;
		}

		addr = temp_res.start;
		size = resource_size(&temp_res);

		block_start[block_num] = addr;
		block_end[block_num] = addr + size;

		__D("got addr size: %#llx %#llx\n", addr, size);

		num_pools = 0;
		if (of_get_property(block, "cmem-buf-pools", &n) != NULL) {
			/*
			 * n is number of bytes, need multiple of (ints_per_pool * 4)
			 */
			if ((n % (ints_per_pool * 4)) != 0) {
				__E("bad cmem-buf-pools: must be multiple of %d ints\n",
				    ints_per_pool);
				return -EINVAL;
			}

			num_pools = n / (ints_per_pool * 4);
		}

		if (num_pools > MAX_POOLS) {
			__E("bad cmem-buf-pools: too many pools\n"
			    "  must be <= %d\n", MAX_POOLS);
				return -EINVAL;
		}

		__D("num_pools=%d\n", num_pools);

		npools[block_num] = num_pools;
		if (!num_pools)
			continue;
		ret = of_property_read_u32_array(block, "cmem-buf-pools",
						 tmp,
						 ints_per_pool * num_pools);
		if (ret)
			continue;

		n = 0;
		p = 0;
		while (num_pools) {
			num_buffers = tmp[n];

			buffer_size = 0;
			for (i = 0; i < pool_size_cells; i++) {
				buffer_size <<= 32;
				buffer_size |= tmp[n + i + 1];
			}
			pool_num_buffers[block_num][p] = num_buffers;
			pool_size[block_num][p] = buffer_size;

			num_pools--;
			p++;
			n += ints_per_pool;

			__D("got a pool: %d x %#llx\n",
			    num_buffers, buffer_size);
		}
	}

	return 0;
}

#endif /* KERNEL_VERSION >= 3.14.0 */

/*
 * cl_config needs to set:
 *   block_start[bi]
 *   block_end[bi]
 *   npools[bi]
 *   pool_num_buffers[bi][p]
 *   pool_size[bi][p]
 * for blocks *not* specified in DT that *are* specified on the command line
 */
int cl_config(void)
{
	char *pstart[NBLOCKS];
	char *pend[NBLOCKS];
	char **pool_table[MAX_POOLS];
	int err = 0;
	int bi;
	int i;
	char *t;

	/* if allowOverlap != -1 then it was set on the command line (to 0 or 1) */
	if (allowOverlap != -1) {
		pr_warn("cmem_init: allowOverlap parameter has been deprecated, ignoring...\n");
	}

	if (npools[0] > MAX_POOLS) {
		__E("Too many pools specified (%d) for Block 0, only %d supported.\n",
		    npools[0], MAX_POOLS);
		return -EINVAL;
	}

	if (npools[1] > MAX_POOLS) {
		__E("Too many pools specified (%d) for Block 1, only %d supported.\n",
		    npools[1], MAX_POOLS);
		return -EINVAL;
	}

	if (npools[2] > MAX_POOLS) {
		__E("Too many pools specified (%d) for Block 2, only %d supported.\n",
		    npools[2], MAX_POOLS);
		return -EINVAL;
	}

/* cut-and-paste below as part of adding support for more than 4 blocks */
	if (npools[3] > MAX_POOLS) {
		__E("Too many pools specified (%d) for Block 3, only %d supported.\n",
		    npools[3], MAX_POOLS);
		return -EINVAL;
	}
/* cut-and-paste above as part of adding support for more than 4 blocks */

	pstart[0] = phys_start;
	pend[0] = phys_end;
	pool_table[0] = pools;

	pstart[1] = phys_start_1;
	pend[1] = phys_end_1;
	pool_table[1] = pools_1;

	pstart[2] = phys_start_2;
	pend[2] = phys_end_2;
	pool_table[2] = pools_2;

/* cut-and-paste below as part of adding support for more than 4 blocks */
	pstart[3] = phys_start_3;
	pend[3] = phys_end_3;
	pool_table[3] = pools_3;
/* cut-and-paste above as part of adding support for more than 4 blocks */

	for (bi = 0; bi < NBLOCKS; bi++) {
		if (!pstart[bi]) {
			continue;
		}

		if (block_start[bi]) {
			__D("block %d specified in DT, ignoring cmd line\n", bi);
			continue;
		}

		/* Get the start and end of CMEM memory */
		block_start[bi] = PAGE_ALIGN(simple_strtoll(pstart[bi], NULL, 16));
		block_end[bi] = PAGE_ALIGN(simple_strtoll(pend[bi], NULL, 16));

		/* Parse the pools */
		for (i = 0; i < npools[bi]; i++) {
			t = strsep(&pool_table[bi][i], "x");
			if (!t) {
				err = -EINVAL;
				goto fail;
			}
			pool_num_buffers[bi][i] = simple_strtol(t, NULL, 10);

			t = strsep(&pool_table[bi][i], "\0");
			if (!t) {
				err = -EINVAL;
				goto fail;
			}
			pool_size[bi][i] = simple_strtoll(t, NULL, 10);
		}
	}

fail:
	return err;
}

static int __init cmem_dma_offset_configure(struct device *dev)
{
#if IS_ENABLED(CONFIG_ARCH_KEYSTONE) && IS_ENABLED(CONFIG_ARM_LPAE)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	dev->dma_pfn_offset = KEYSTONE_DMA_PFN_OFFSET;
	return 0;
#else
	return dma_direct_set_offset(dev, KEYSTONE_HIGH_PHYS_START,
					KEYSTONE_LOW_PHYS_START,
					KEYSTONE_HIGH_PHYS_SIZE);
#endif
#else
	return 0;
#endif
}

int __init cmem_init(void)
{
	int bi;
	int i;
	int err;
	unsigned long long length;
	HeapMem_Header *header;
	char tmp_str[4];
	void *virtp;

	banner();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	if ((err = dt_config()) == -EINVAL) {
		__E("bad DT config\n");
		return err;
	}
	else {
		if (err == -ENODEV) {
			__D("no DT config\n");
		}
	}
#endif /* KERNEL_VERSION >= 3.14.0 */

	if ((err = cl_config()) != 0) {
		__E("error %d processing command line\n", err);
		return err;
	}

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

	/* Create cmem device */
	cmem_cma_dev_0 = device_create(cmem_class, NULL, MKDEV(cmem_major, 0),
				   NULL, "cmem");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	cmem_cma_dev_0->coherent_dma_mask = DMA_BIT_MASK(32);
	err = cmem_dma_offset_configure(cmem_cma_dev_0);
	if (err) {
		__E("cmem_dma_offset_configure failed.\n");
		goto fail_after_dma;
	}
#endif
	for (bi = 0; bi < NBLOCKS; bi++) {
		if (!block_start[bi] || !block_end[bi]) {
			if (bi != 0) {
				continue;
			}

			/* we know block 0 wasn't specified, ensure no pools for it */
			if (pool_num_buffers[0][0]) {
				__E("pools specified: must specify both phys_start and phys_end, exiting...\n");
				err = -EINVAL;
				goto fail_after_create;
			} else {
				printk(KERN_INFO "no physical memory specified\n");

				break;
			}
		}

		length = block_end[bi] - block_start[bi];

		if (block_start[bi] == 0) {
			sprintf(tmp_str, "_%d", bi);
			__E("Physical address of 0 not allowed (phys_start%s)\n",
			    bi == 0 ? "" : tmp_str);
			__E("  (minimum physical address is %#lx)\n", PAGE_SIZE);
			err = -EINVAL;
			goto fail_after_create;
		}

		if (block_end[bi] < block_start[bi]) {
			__E("phys_end (%#llx) < phys_start (%#llx)\n",
			    block_end[bi], block_start[bi]);
			err = -EINVAL;
			goto fail_after_create;
		}

		block_avail_size[bi] = length;

		if (block_type[bi] != BLOCK_TYPE_SRAM_NODE) {
			__D("calling request_mem_region(%#llx, %#llx, \"CMEM\")\n",
			    block_start[bi], length);

			if (!request_mem_region(block_start[bi], length, "CMEM")) {
				__E("Failed to request_mem_region(%#llx, %#llx)\n",
				    block_start[bi], length);
				err = -EFAULT;
				goto fail_after_create;
			}
		}

		block_flags[bi] |= BLOCK_MEMREGION;

		/* Allocate the pools */
		for (i = 0; i < npools[bi]; i++) {
			if (alloc_pool(bi, i, pool_num_buffers[bi][i], pool_size[bi][i],
				       NULL) < 0) {
				__E("Failed to alloc pool of size 0x%llu and number of buffers %d\n", pool_size[bi][i], pool_num_buffers[bi][i]);
				err = -ENOMEM;
				goto fail_after_create;
			}

			total_num_buffers[bi] += pool_num_buffers[bi][i];
		}

		/* use whatever is left for the heap */
		heap_size[bi] = block_avail_size[bi] & PAGE_MASK;
		if (heap_size[bi] > 0) {
			err = alloc_pool(bi, npools[bi], 1, heap_size[bi], &heap_physp[bi]);
			if (err < 0) {
				__E("Failed to alloc heap of size %#lx\n", heap_size[bi]);
				goto fail_after_create;
			}
			printk(KERN_INFO "allocated heap buffer %#llx of size %#lx\n",
			       (unsigned long long)heap_physp[bi], heap_size[bi]);
			heap_pool[bi] = npools[bi];
			heap_head[bi].next = heap_physp[bi];
			heap_head[bi].size = heap_size[bi];

			err = map_header((void **)&virtp, heap_physp[bi]);
			if (err < 0) {
				__E("Failed to alloc pool of size 0x%llu and number of buffers %d\n", pool_size[bi][i], pool_num_buffers[bi][i]);
				err = -ENOMEM;

				goto fail_after_create;
			}

			header = (HeapMem_Header *)virtp;
			header->next = 0;
			header->size = heap_size[bi];

			unmap_header(virtp);

			if (useHeapIfPoolUnavailable) {
				printk(KERN_INFO "heap fallback enabled - will try heap if "
				       "pool buffer is not available\n");
			}
		} else {
			__D("no remaining memory for heap, no heap created "
			    "for memory block %d\n", bi);
			heap_head[bi].next = 0;
		}

		__D("cmem initialized %d pools between %#llx and %#llx\n",
			   npools[bi], block_start[bi], block_end[bi]);

		nblocks++;
	}


	if (cmem_cma_npools == 0) {
		/* no explicit pools, assuming global CMA area */
		__D("no CMEM CMA pools found\n");

		INIT_LIST_HEAD(&p_objs[NBLOCKS][0].busylist);
		p_objs[NBLOCKS][0].reqsize = 0;
		p_objs[NBLOCKS][0].size = 0;
		p_objs[NBLOCKS][0].numbufs = 1;

		heap_pool[NBLOCKS] = 0;
		npools[NBLOCKS] = 0;
	} else {
		__D("%d CMEM CMA pools\n", cmem_cma_npools);

		for (i = 0; i < cmem_cma_npools; i++) {
			INIT_LIST_HEAD(&p_objs[NBLOCKS][i].busylist);
			p_objs[NBLOCKS][i].reqsize = cmem_cma_p_objs[i].reqsize;
			p_objs[NBLOCKS][i].size = cmem_cma_p_objs[i].size;
			p_objs[NBLOCKS][i].numbufs = cmem_cma_p_objs[i].numbufs;

			cmem_cma_dev[i].coherent_dma_mask = DMA_BIT_MASK(32);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
			cmem_dma_offset_configure(&cmem_cma_dev[i]);
#endif
			__D("	pool %d: size=%#llx numbufs=%d\n", i,
				p_objs[NBLOCKS][i].size, p_objs[NBLOCKS][i].numbufs);
		}

		if (cmem_cma_heapsize) {
			/* already init'ed p_objs in loop above */
			heap_pool[NBLOCKS] = cmem_cma_npools - 1;
			npools[NBLOCKS] = cmem_cma_npools - 1;
		} else {
			INIT_LIST_HEAD(&p_objs[NBLOCKS][cmem_cma_npools].busylist);
			p_objs[NBLOCKS][cmem_cma_npools].reqsize = 0;
			p_objs[NBLOCKS][cmem_cma_npools].size = 0;
			p_objs[NBLOCKS][cmem_cma_npools].numbufs = 1;

			heap_pool[NBLOCKS] = cmem_cma_npools;
			npools[NBLOCKS] = cmem_cma_npools;
		}
	}

	/* Create the /proc entry */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
	cmem_proc_entry = proc_create("cmem", 0, NULL, &cmem_proc_fops);
#else
	cmem_proc_entry = proc_create("cmem", 0, NULL, &cmem_proc_ops);
#endif
	printk(KERN_INFO "cmemk initialized\n");

	return 0;

fail_after_create:

	length = block_end[bi] - block_start[bi];

	for (bi = 0; bi < NBLOCKS; bi++) {
		if (block_flags[bi] & BLOCK_MEMREGION) {
			__D("calling release_mem_region(%#llx, %#llx)...\n",
			    block_start[bi], length);

			if (block_type[bi] != BLOCK_TYPE_SRAM_NODE)
				release_mem_region(block_start[bi], length);

				block_flags[bi] &= ~BLOCK_MEMREGION;
		}
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
fail_after_dma:
#endif
	device_destroy(cmem_class, MKDEV(cmem_major, 0));
	class_destroy(cmem_class);

fail_after_reg:
	__D("Unregistering character device cmem\n");
	unregister_chrdev(cmem_major, "cmem");

	return err;
}

void __exit cmem_exit(void)
{
	struct list_head *registeredlistp;
	struct list_head *freelistp;
	struct list_head *busylistp;
	struct list_head *e;
	struct list_head *u;
	struct list_head *unext;
	struct pool_buffer *entry;
	struct registered_user *user;
	unsigned long long length;
	int num_pools;
	int bi;
	int i;

	__D("In cmem_exit()\n");

	/* Remove the /proc entry */
	remove_proc_entry("cmem", NULL);

	for (bi = 0; bi < NBLOCKS; bi++) {
		num_pools = npools[bi];

		if (heap_pool[bi] != -1) {
			num_pools++;
		}

		/* Free the pool structures and empty the lists. */
		for (i = 0; i < num_pools; i++) {
			__D("Freeing memory associated with pool %d\n", i);

			freelistp = &p_objs[bi][i].freelist;
			busylistp = &p_objs[bi][i].busylist;

			e = busylistp->next;
			while (e != busylistp) {
				entry = list_entry(e, struct pool_buffer, element);

				__D("Warning: Freeing busy entry %d at %#llx\n",
				    entry->id, (unsigned long long)entry->physp);

				registeredlistp = &entry->users;
				u = registeredlistp->next;
				while (u != registeredlistp) {
					unext = u->next;

					user = list_entry(u, struct registered_user, element);

					__D("Removing file 0x%p from user list of buffer %#llx...\n",
					user->filp, (unsigned long long)entry->physp);

					list_del(u);
					kfree(user);

					u = unext;
				}

				e = e->next;
				kfree(entry);
			}

			e = freelistp->next;
			while (e != freelistp) {
				entry = list_entry(e, struct pool_buffer, element);

				__D("Freeing free entry %d at %#llx\n",
				    entry->id, (unsigned long long)entry->physp);

				registeredlistp = &entry->users;
				u = registeredlistp->next;
				while (u != registeredlistp) {
					/* should never happen, but check to avoid mem leak */
					unext = u->next;

					user = list_entry(u, struct registered_user, element);

					__D("Removing file 0x%p from user list of buffer %#llx...\n",
					user->filp, (unsigned long long)entry->physp);

					list_del(u);
					kfree(user);

					u = unext;
				}

				e = e->next;
				kfree(entry);
			}
		}

		length = block_end[bi] - block_start[bi];

		if (block_flags[bi] & BLOCK_MEMREGION) {
			__D("calling release_mem_region(%#llx, %#llx)...\n",
			    block_start[bi], length);

			if (block_type[bi] != BLOCK_TYPE_SRAM_NODE)
				release_mem_region(block_start[bi], length);

				block_flags[bi] &= ~BLOCK_MEMREGION;
		}
	}

	device_destroy(cmem_class, MKDEV(cmem_major, 0));
	class_destroy(cmem_class);

	__D("Unregistering character device cmem\n");
	unregister_chrdev(cmem_major, "cmem");

	printk(KERN_INFO "cmemk unregistered\n");
}

MODULE_LICENSE("GPL");
module_init(cmem_init);
module_exit(cmem_exit);

#ifndef DISABLE_CACHE_OPERATIONS
#if  !defined(dmac_map_range)

#if !defined(MULTI_CACHE)

//#warning "dmac_map_range is *not* #defined, using work-around for asm cache functions"

#ifdef CONFIG_CPU_ARM926T

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
@	cmp     r2, #DMA_TO_DEVICE\n \
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
@	tst     r1, #CACHE_DLINESIZE - 1\n \
	tst     r1, #32 - 1\n \
	mcrne   p15, 0, r1, c7, c10, 1          @ clean D entry\n \
@	bic     r0, r0, #CACHE_DLINESIZE - 1\n \
	bic     r0, r0, #32 - 1\n \
1:	mcr     p15, 0, r0, c7, c6, 1           @ invalidate D entry\n \
@	add     r0, r0, #CACHE_DLINESIZE\n \
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
@	bic     r0, r0, #CACHE_DLINESIZE - 1\n \
	bic     r0, r0, #32 - 1\n \
1:	mcr     p15, 0, r0, c7, c10, 1          @ clean D entry\n \
@	add     r0, r0, #CACHE_DLINESIZE\n \
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
@	bic     r0, r0, #CACHE_DLINESIZE - 1\n \
	bic     r0, r0, #32 - 1\n \
1:\n \
	mcr     p15, 0, r0, c7, c14, 1          @ clean+invalidate D entry\n \
@	add     r0, r0, #CACHE_DLINESIZE\n \
	add     r0, r0, #32\n \
	cmp     r0, r1\n \
	blo     1b\n \
	mcr     p15, 0, r0, c7, c10, 4          @ drain WB\n \
	mov     pc, lr\n \
");

#else  /* CONFIG_CPU_ARM926T */

/*
 *	v7_dma_inv_range(start,end)
 *
 *	Invalidate the data cache within the specified region; we will
 *	be performing a DMA operation in this region and we want to
 *	purge old data in the cache.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
asm("\n \
	.global v7_dma_inv_range\n \
v7_dma_inv_range:\n \
@	dcache_line_size r2, r3\n \
	mrc     p15, 0, r3, c0, c0, 1         @ read ctr\n \
	lsr     r3, r3, #16\n \
	and     r3, r3, #0xf                @ cache line size encoding\n \
	mov     r2, #4                        @ bytes per word\n \
	mov     r2, r2, lsl r3            @ actual cache line size\n \
\n \
	sub	r3, r2, #1\n \
	tst	r0, r3\n \
	bic	r0, r0, r3\n \
@ #ifdef CONFIG_ARM_ERRATA_764369\n \
@ 	ALT_SMP(W(dsb))\n \
@ 	ALT_UP(W(nop))\n \
@ #endif\n \
	mcrne	p15, 0, r0, c7, c14, 1		@ clean & invalidate D / U line\n \
	tst	r1, r3\n \
	bic	r1, r1, r3\n \
	mcrne	p15, 0, r1, c7, c14, 1		@ clean & invalidate D / U line\n \
1:\n \
	mcr	p15, 0, r0, c7, c6, 1		@ invalidate D / U line\n \
	add	r0, r0, r2\n \
	cmp	r0, r1\n \
	blo	1b\n \
	dsb\n \
	mov	pc, lr\n \
");

/*
 *	v7_dma_clean_range(start,end)
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
asm("\n \
	.global v7_dma_clean_range\n \
v7_dma_clean_range:\n \
@	dcache_line_size r2, r3\n \
	mrc     p15, 0, r3, c0, c0, 1         @ read ctr\n \
	lsr     r3, r3, #16\n \
	and     r3, r3, #0xf                @ cache line size encoding\n \
	mov     r2, #4                        @ bytes per word\n \
	mov     r2, r2, lsl r3            @ actual cache line size\n \
\n \
	sub	r3, r2, #1\n \
	bic	r0, r0, r3\n \
@ #ifdef CONFIG_ARM_ERRATA_764369\n \
@ 	ALT_SMP(W(dsb))\n \
@ 	ALT_UP(W(nop))\n \
@ #endif\n \
1:\n \
	mcr	p15, 0, r0, c7, c10, 1		@ clean D / U line\n \
	add	r0, r0, r2\n \
	cmp	r0, r1\n \
	blo	1b\n \
	dsb\n \
	mov	pc, lr\n \
");

/*
 *	v7_dma_flush_range(start,end)
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
asm("\n \
	.global v7_dma_flush_range\n \
v7_dma_flush_range:\n \
@	dcache_line_size r2, r3\n \
	mrc     p15, 0, r3, c0, c0, 1         @ read ctr\n \
	lsr     r3, r3, #16\n \
	and     r3, r3, #0xf                @ cache line size encoding\n \
	mov     r2, #4                        @ bytes per word\n \
	mov     r2, r2, lsl r3            @ actual cache line size\n \
\n \
	sub	r3, r2, #1\n \
	bic	r0, r0, r3\n \
@ #ifdef CONFIG_ARM_ERRATA_764369\n \
@ 	ALT_SMP(W(dsb))\n \
@ 	ALT_UP(W(nop))\n \
@ #endif\n \
1:\n \
	mcr	p15, 0, r0, c7, c14, 1		@ clean & invalidate D / U line\n \
	add	r0, r0, r2\n \
	cmp	r0, r1\n \
	blo	1b\n \
	dsb\n \
	mov	pc, lr\n \
");

/*
 *	dma_map_area(start, size, dir)
 *	- start	- kernel virtual start address
 *	- size	- size of region
 *	- dir	- DMA direction
 */
asm("\n \
	.global v7_dma_map_area\n \
v7_dma_map_area:\n \
	add	r1, r1, r0\n \
@	cmp     r2, #DMA_TO_DEVICE\n \
	cmp     r2, #1\n \
	beq     v7_dma_clean_range\n \
	bcs     v7_dma_inv_range\n \
	b       v7_dma_flush_range\n \
");

/*
 *	dma_unmap_area(start, size, dir)
 *	- start	- kernel virtual start address
 *	- size	- size of region
 *	- dir	- DMA direction
 */
asm("\n \
	.global v7_dma_unmap_area\n \
v7_dma_unmap_area:\n \
	add	r1, r1, r0\n \
@	teq	r2, #DMA_TO_DEVICE\n \
	teq	r2, #1\n \
	bne	v7_dma_inv_range\n \
	mov	pc, lr\n \
");

#endif /* CONFIG_CPU_ARM926T */

#endif /* !defined(MULTI_CACHE) */

#endif /* dmac_map_range */

#endif /* DISABLE_CACHE_OPERATIONS */
