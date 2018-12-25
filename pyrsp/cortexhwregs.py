#!/usr/bin/env python

from construct import BitStruct, BitsInteger, Padding, Enum, Flag

SCB_ICSR = 0xe000ed04
scb_icsr = BitStruct(
                     "NMIPENDSET" / Flag,
                     Padding(2),
                     "PENDSVSET" / Flag,
                     "PENDSVCLR" / Flag,
                     "PENDSTSET" / Flag,
                     "PENDSTCLR" / Flag,
                     Padding(1),
                     "DEBUG" / Flag,
                     "ISRPENDING" / Flag,
                     "VECTPENDING" / BitsInteger(10),
                     "RETOBASE" / Flag,
                     Padding(2),
                     "VECTACTIVE" / BitsInteger(9)
                     )

SCB_SHCSR = 0xe000ed24
scb_shcsr = BitStruct(
                     Padding(13),
                      "USGFAULTENA" / Flag,
                      "BUSFAULTENA" / Flag,
                      "MEMFAULTENA" / Flag,
                      "SVCALLPENDED"/ Flag,
                      "BUSFAULTPENDED" / Flag,
                      "MEMFAULTPENDED" / Flag,
                      "USGFAULTPENDED" / Flag,
                      "SYSTICKACT" / Flag,
                      "PENDSVACT" / Flag,
                      Padding(1),
                      "MONITORACT" / Flag,
                      "SVCALLACT" / Flag,
                      Padding(3),
                      "USGFAULTACT" / Flag,
                      Padding(1),
                      "BUSFAULTACT" / Flag,
                      "MEMFAULTACT" / Flag,
                      )

SCB_CFSR = 0xe000ed28
scb_cfsr = BitStruct(
                     Padding(6),
                     "DIVBYZERO" / Flag,
                     "UNALIGNED" / Flag,
                     Padding(4),
                     "NOCP" / Flag,
                     "INVPC" / Flag,
                     "INVSTATE" / Flag,
                     "UNDEFINSTR" / Flag,
                     "BFARVALID" / Flag,
                     Padding(2),
                     "STKERR" / Flag,
                     "UNSTKERR" / Flag,
                     "IMPRECISERR" / Flag,
                     "PRECISERR" / Flag,
                     "IBUSERR" / Flag,
                     "MMARVALID" / Flag,
                     Padding(2),
                     "MSTKERR" / Flag,
                     "MUNSTKERR" / Flag,
                     Padding(1),
                     "DACCVIOL" / Flag,
                     "IACCVIOL" / Flag,
                     )

SCB_HFSR = 0xe000ed2c
scb_hfsr = BitStruct(
                     "DEBUG_VT" / Flag,
                     "FORCED" / Flag,
                     Padding(28),
                     "VECTTBL" / Flag,
                     Padding(1),
                     )
SCB_MMFAR = 0xe000ed34
SCB_BFAR = 0xe000ed38

MPU_TYPER = 0xe000ed90
MPU_CR = 0xe000ed94
mpu_cr = BitStruct(
                   Padding(29),
                   "PRIVDEFENA" / Flag,
                   "HFNMIENA" / Flag,
                   "ENABLE" / Flag,
                   )

MPU_RNR = 0xe000ed98
mpu_rnr = BitStruct(
                    Padding(24),
                    "REGION" / BitsInteger(8))

MPU_RBAR = 0xe000ed9c
mpu_rbar = BitStruct(
                     "ADDR" / BitsInteger(27),
                     "VALID" / Flag,
                     "REGION" / BitsInteger(4))

MPU_RASR = 0xe000eda0
mpu_rasr = BitStruct(
                     Padding(3),
                     "XN" / Flag,
                     Padding(1),
                     #BitField("AP", 3),
                     Enum("AP" / BitsInteger(3),
                          No_access = 0,
                          RW_No_access = 1,
                          RW_RO = 2,
                          RW = 3,
                          RO_No_access = 5,
                          RO = 6,
                          INV7 = 7),
                     Padding(2),
                     #BitField("TEX", 3), #Flag("S", 1), #Flag("C", 1), #Flag("B", 1),
                     Enum("TEXSCB" / BitsInteger(6),
                          UNSET   =(0b000000),
                          FLASH_RAM   =(0b000010),
                          INTERNAL_RAM=(0b000110),
                          EXTERNAL_RAM=(0b000111),
                          PERIPHERIALS=(0b000101),),
                     "SRD" / BitsInteger(8),
                     Padding(2),
                     #BitField("SIZE", 5),
                     Enum("SIZE" / BitsInteger(5),
                         unset   =(0b00000), invalid1=(0b00001), invalid2=(0b00010), invalid3=(0b00011),
                         _32B    =(0b00100), _64B    =(0b00101), _128B   =(0b00110), _256B   =(0b00111),
                         _512B   =(0b01000), _1KB    =(0b01001), _2KB    =(0b01010), _4KB    =(0b01011),
                         _8KB    =(0b01100), _16KB   =(0b01101), _32KB   =(0b01110), _64KB   =(0b01111),
                         _128KB  =(0b10000), _256KB  =(0b10001), _512KB  =(0b10010), _1MB    =(0b10011),
                         _2MB    =(0b10100), _4MB    =(0b10101), _8MB    =(0b10110), _16MB   =(0b10111),
                         _32MB   =(0b11000), _64MB   =(0b11001), _128MB  =(0b11010), _256MB  =(0b11011),
                         _512MB  =(0b11100), _1GB    =(0b11101), _2GB    =(0b11110), _4GB    =(0b11111),
                     ),
                     "Enabled" / Flag)
