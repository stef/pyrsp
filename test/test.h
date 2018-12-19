#ifndef __TEST_H
#define __TEST_H

#ifdef __i386__
#define ARG_ON_REG __attribute__((fastcall))
#else
#define ARG_ON_REG
#endif

#define KiB(n) ((n) << 10)
#define ASIZE(a) (sizeof(a) / sizeof((a)[0]))

#endif // __TEST_H
