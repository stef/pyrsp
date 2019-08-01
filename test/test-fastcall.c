#include "test.h"

ARG_ON_REG void foo(int val)
{
    /* nop */
}

void main(void)
{
    foo(0xDEADBEEF);
}
