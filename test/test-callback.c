#include "test.h"

typedef void (*Callback)(void);

void callback(void)
{
    /* nop */
}

ARG_ON_REG void caller(Callback cb)
{
    cb();
}

void main(void)
{
    caller(callback);
}
