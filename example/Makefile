PREFIX = arm-none-eabi
CC=$(PREFIX)-gcc
LD=$(PREFIX)-ld
OC=$(PREFIX)-objcopy
AS=$(PREFIX)-as

CFLAGS = -DTEST -mno-unaligned-access -g -Wall -Werror -Os \
	-mfix-cortex-m3-ldrd -msoft-float -mthumb -Wno-strict-aliasing \
	-fomit-frame-pointer $(INCLUDES) -mcpu=cortex-m3

LDFLAGS = -mthumb -mcpu=cortex-m3 -fno-common -Tmemmap -nostartfiles -Wl,--gc-sections -Wl,-z,relro

objs = test.o rsp.o

all : test.bin

test.bin : memmap $(objs)
	$(CC) $(LDFLAGS) -o test.elf $(objs) $(LIBS)
	$(OC) test.elf test.bin -O binary

clean:
	rm -f *.bin
	rm -f $(objs)
	rm -f *.elf

.PHONY: clean
