/*
 * cmemk_stub.c
 */
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <linux/cmemk_stub.h>

int cmem_npools = 1;
int cmem_heapsize = 0;
struct device cmem_dev[CMEM_MAXPOOLS];
struct pool_object cmem_p_objs[CMEM_MAXPOOLS];

EXPORT_SYMBOL(cmem_npools);
EXPORT_SYMBOL(cmem_heapsize);
EXPORT_SYMBOL(cmem_dev);
EXPORT_SYMBOL(cmem_p_objs);

static int __init early_cmemheapsize(char *p)
{
    cmem_heapsize = memparse(p, NULL);
    cmem_p_objs[0].reqsize = cmem_heapsize;
    cmem_p_objs[0].numbufs = 1;

    pr_debug("cmemheapsize: heapsize=0x%x\n", cmem_heapsize);

    return 0;
}
early_param("cmem_heapsize", early_cmemheapsize);

static int __init early_cmempools(char *p)
{
    int done = 0;
    int n;
    char *x;

    do {
	x = strchr(p, 'x');
	if (x != NULL) {
	    *x = '\0';
	    n = cmem_npools;
	    if (n == CMEM_MAXPOOLS) {
		pr_err("cmempools: CMEM_MAXPOOLS reached!\n");

		break;
	    }
	    cmem_p_objs[n].numbufs = memparse(p, NULL);
	    cmem_p_objs[n].reqsize = memparse(x + 1, &x);

	    pr_debug("cmempools: pool %d = %d * 0x%x\n", n, cmem_p_objs[n].numbufs, cmem_p_objs[n].reqsize);

	    cmem_npools++;

	    if (*x++ == ',') {
		p = x;
	    }
	    else {
		done = 1;
	    }
	}
	else {
	    done = 1;
	}
    } while (!done);

    return 0;
}
early_param("cmem_pools", early_cmempools);


struct page *cmem_alloc(struct device *dev, int count, int order)
{
    return dma_alloc_from_contiguous(dev, count, order);
}
EXPORT_SYMBOL(cmem_alloc);


int cmem_release(struct device *dev, struct page *page, int count)
{
    return dma_release_from_contiguous(dev, page, count);
}
EXPORT_SYMBOL(cmem_release);

static void cmem_device_release(struct device *dev)
{
    pr_debug("cmem_device_release(%p)...\n", dev);

    put_device(dev);
}


/* this function is registered in arch/arm/plat-omap/common.c */
void __init cmem_reserve_cma(void)
{
    int poolsize;
    int reqsize;
    int size;
    int nbufs;
    int i;
    int rv;

    pr_debug("cmem_reserve_cma()...\n");

    for (i = 0; i < cmem_npools; i++) {
	if (i == 0) {
	    pr_debug("cmem_reserve_cma: heapsize 0x%x specified\n", cmem_heapsize);
	}
	reqsize = cmem_p_objs[i].reqsize;
	if (reqsize != 0) {
	    nbufs = cmem_p_objs[i].numbufs;
	    size = round_up(reqsize, PAGE_SIZE);
	    poolsize = nbufs * size;
	    rv = dma_declare_contiguous(&cmem_dev[i], poolsize, 0, 0xffffffff);

	    if (rv) {
		pr_err("cmem_reserve_cma: dma_declare_contiguous failed %d\n", rv);

		/* size of 0 means no buffers available */
		cmem_p_objs[i].size = 0;
	    }
	    else {
		pr_debug("cmem_reserve_cma: dma_declare_contiguous succeeded\n");
		cmem_dev[i].release = cmem_device_release;

		/* numbufs and reqsize already set in early_cmempools() */
		INIT_LIST_HEAD(&cmem_p_objs[i].busylist);
		cmem_p_objs[i].size = size;
	    }
	}
	else {
	    INIT_LIST_HEAD(&cmem_p_objs[i].busylist);
	}
    }
}

#if 0
void __init test_dma_contig(struct device *dev, int count, int order)
{
    struct page *cma_page[16];
    void *va;
    int i;

    for (i = 0; i < 16; i++) {
	cma_page[i] = dma_alloc_from_contiguous(dev, count, order);
	if (!cma_page[i]) {
	    printk("dma_alloc_from_contiguous(%p, %d, %d) failed\n", dev, count, order);
	}
	else {
	    printk("dma_alloc_from_contiguous(%p, %d, %d) SUCCEEDED: page=%p pfn=0x%lx(000)\n", dev, count, order, cma_page[i], page_to_pfn(cma_page[i]));
	    va = page_address(cma_page[i]);
//	    printk("page_address()=%p, getPhys(%p)=0x%lx\n", va, va, get_phys((unsigned long)va));
	    printk("page_address()=%p, getPhys(%p)=0x%lx\n", va, va, page_to_pfn(cma_page[i]) << PAGE_SHIFT);
	}
    }
    for (i = 0; i < 16; i++) {
	if (cma_page[i]) {
	    printk("dma_release_from_contiguous(%p, %p, %d)...\n", dev, cma_page[i], count);
	    dma_release_from_contiguous(dev, cma_page[i], count);
	}
    }
}

void __init cmem_test_init(void)
{
    printk("cmem_test_init(): calling test_dma_contig(1, 0)...\n");

    test_dma_contig(&cmem_dev[0], 1, 0);
    test_dma_contig(&cmem_dev[0], 2, 0);
    test_dma_contig(&cmem_dev[0], 4, 0);
    test_dma_contig(&cmem_dev[0], 1, 1);
    test_dma_contig(&cmem_dev[0], 2, 1);
    test_dma_contig(&cmem_dev[0], 4, 1);
    test_dma_contig(&cmem_dev[0], 1, 2);
    test_dma_contig(&cmem_dev[0], 2, 2);
    test_dma_contig(&cmem_dev[0], 4, 2);
    test_dma_contig(&cmem_dev[0], 1, 3); // order 3 = pages aligned to 0x8000
    test_dma_contig(&cmem_dev[0], 8, 3);
    test_dma_contig(&cmem_dev[0], 9, 3);
    test_dma_contig(&cmem_dev[0], 16, 3);

    printk("...done\n");
}
#endif

MODULE_LICENSE("GPL");

