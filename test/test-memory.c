#include "test.h"

ARG_ON_REG void rsp_dump(void *ptr, unsigned long size)
{
}

void main(void)
{
    char data[KiB(NUB_KIBS)];

    for (int i = 0; i < ASIZE(data); i++) {
        /* 'f' (0x66) results in hexadecimal string of '6' when reading memory
         through RSP. It is run-length encoded by GDB. */
        data[i] = 'f';
    }

    rsp_dump(data, ASIZE(data));
}
