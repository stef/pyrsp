#ifndef __TEST_H
#define __TEST_H

#ifdef __i386__
#define ARG_ON_REG __attribute__((fastcall))
#else
#define ARG_ON_REG
#endif

#endif // __TEST_H
