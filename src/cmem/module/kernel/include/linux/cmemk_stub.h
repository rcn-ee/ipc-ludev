/**
 *  @defgroup   ti_sdo_linuxutils_cmem_CMEM  Contiguous Memory Manager
 *
 *  This is the API for the Contiguous Memory Manager.
 */

#ifndef _CMEMK_STUB_H
#define _CMEMK_STUB_H

#if defined (__cplusplus)
extern "C" {
#endif

#define CMEM_MAXPOOLS 8

struct pool_object {
    struct list_head busylist;
    unsigned int numbufs;
    unsigned int size;
    unsigned int reqsize;
};

extern struct pool_object cmem_p_objs[CMEM_MAXPOOLS];
extern struct device cmem_dev[CMEM_MAXPOOLS];
extern int cmem_heapsize;
extern int cmem_npools;

extern struct page *cmem_alloc(struct device *dev, int count, int order);
extern int cmem_release(struct device *dev, struct page *page, int count);

#if defined (__cplusplus)
}
#endif

#endif
