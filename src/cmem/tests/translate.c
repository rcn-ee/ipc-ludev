/*
 * translate.c
 *
 * Tests the address translation. Inserting CMEM with the following
 * options works on the DVEVM (if mem=120M):
 *
 * insmod cmemk.ko phys_start=0x87800000 phys_end=0x88000000 pools=1x3145728 
 *
 * You should see lots of address translations on screen keeping "even steps"
 * as the increase (same offset).
 */

#include <stdio.h>
#include <stdlib.h>

#include <ti/cmem.h>

#define BUFSIZE 1024 * 1024 * 3

int main(int argc, char *argv[])
{
    unsigned char *ptr, *orig;
    unsigned long physp;
    int i;
    int inc;
    

    /* First initialize the CMEM module */
    if (CMEM_init() == -1) {
        fprintf(stderr, "Failed to initialize CMEM\n");
        exit(EXIT_FAILURE);
    }

    printf("CMEM initialized.\n");

    /* First allocate a buffer from the pool that best fits */
    ptr = CMEM_alloc(BUFSIZE, NULL);

    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate buffer of size %d\n", BUFSIZE);
        CMEM_exit();
        exit(EXIT_FAILURE);
    }

    printf("Allocated buffer of size %d at virtual address %#x.\n", BUFSIZE,
           (unsigned int) ptr);

    orig = ptr;

    inc = 4096;
    printf("\nUsing inc = %d\n", inc);
    for (i=0; i<BUFSIZE; i+=inc) {
        physp = CMEM_getPhys(ptr);

        if (physp == 0) {
            fprintf(stderr, "Failed to get physical address of %#x\n",
                    (unsigned int) ptr);
            goto cleanup;
        }

        printf("virtual=%#x physical=%#x\n", (unsigned int) ptr,
                                             (unsigned int) physp);

        ptr += inc;
    } 

    ptr = orig;
    inc = 4096 / 2;
    printf("\nUsing inc = %d\n", inc);
    for (i=0; i<BUFSIZE; i+=inc) {
        physp = CMEM_getPhys(ptr);

        if (physp == 0) {
            fprintf(stderr, "Failed to get physical address of %#x\n",
                    (unsigned int) ptr);
            goto cleanup;
        }

        printf("virtual=%#x physical=%#x\n", (unsigned int) ptr,
                                             (unsigned int) physp);

        ptr += inc;
    } 

    ptr = orig;
    inc = 4096 / 3;
    printf("\nUsing inc = %d\n", inc);
    for (i=0; i<BUFSIZE; i+=inc) {
        physp = CMEM_getPhys(ptr);

        if (physp == 0) {
            fprintf(stderr, "Failed to get physical address of %#x\n",
                    (unsigned int) ptr);
            goto cleanup;
        }

        printf("virtual=%#x physical=%#x\n", (unsigned int) ptr,
                                             (unsigned int) physp);

        ptr += inc;
    } 

    ptr = orig;
    inc = 4096 / 4;
    printf("\nUsing inc = %d\n", inc);
    for (i=0; i<BUFSIZE; i+=inc) {
        physp = CMEM_getPhys(ptr);

        if (physp == 0) {
            fprintf(stderr, "Failed to get physical address of %#x\n",
                    (unsigned int) ptr);
            goto cleanup;
        }

        printf("virtual=%#x physical=%#x\n", (unsigned int) ptr,
                                             (unsigned int) physp);

        ptr += inc;
    }
 
cleanup:
    ptr = orig;
    if (CMEM_free(ptr, NULL) < 0) {
        fprintf(stderr, "Failed to free buffer at %#x\n",
                (unsigned int) ptr);
    }

    printf("Successfully freed buffer at %#x.\n", (unsigned int) ptr);

    if (CMEM_exit() < 0) {
        fprintf(stderr, "Failed to finalize the CMEM module\n");
    }

    exit(EXIT_SUCCESS);
}
