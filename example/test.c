#include "rsp.h"

void test(void) {
  unsigned int number = 0;
  rsp_dump((unsigned char*) &number, 4);
  rsp_dump((unsigned char*) "hello world",11);
  number = 0xaa55aa55;
  rsp_dump((unsigned char*) &number, 4);
  rsp_finish();
}
