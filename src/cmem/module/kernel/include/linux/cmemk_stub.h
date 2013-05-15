/*
 *  Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com
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
