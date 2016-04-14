#!/usr/bin/env python

from construct import BitStruct, BitField, Padding, Enum, Flag

SCB_ICSR = 0xe000ed04
scb_icsr = BitStruct("scb_icsr",
                     Flag('NMIPENDSET'),
                     Padding(2),
                     Flag('PENDSVSET'),
                     Flag('PENDSVCLR'),
                     Flag('PENDSTSET'),
                     Flag('PENDSTCLR'),
                     Padding(1),
                     Flag('DEBUG'),
                     Flag('ISRPENDING'),
                     BitField('VECTPENDING', 10),
                     Flag('RETOBASE'),
                     Padding(2),
                     BitField('VECTACTIVE', 9),
                     )

SCB_SHCSR = 0xe000ed24
scb_shcsr = BitStruct("scb_shcsr",
                     Padding(13),
                      Flag('USGFAULTENA'),
                      Flag('BUSFAULTENA'),
                      Flag('MEMFAULTENA'),
                      Flag('SVCALLPENDED'),
                      Flag('BUSFAULTPENDED'),
                      Flag('MEMFAULTPENDED'),
                      Flag('USGFAULTPENDED'),
                      Flag('SYSTICKACT'),
                      Flag('PENDSVACT'),
                      Padding(1),
                      Flag('MONITORACT'),
                      Flag('SVCALLACT'),
                      Padding(3),
                      Flag('USGFAULTACT'),
                      Padding(1),
                      Flag('BUSFAULTACT'),
                      Flag('MEMFAULTACT'))

SCB_CFSR = 0xe000ed28
scb_cfsr = BitStruct("scb_cfsr",
                     Padding(6),
                     Flag("DIVBYZERO"),
                     Flag("UNALIGNED"),
                     Padding(4),
                     Flag("NOCP"),
                     Flag("INVPC"),
                     Flag("INVSTATE"),
                     Flag("UNDEFINSTR"),
                     Flag("BFARVALID"),
                     Padding(2),
                     Flag("STKERR"),
                     Flag("UNSTKERR"),
                     Flag("IMPRECISERR"),
                     Flag("PRECISERR"),
                     Flag("IBUSERR"),
                     Flag("MMARVALID"),
                     Padding(2),
                     Flag("MSTKERR"),
                     Flag("MUNSTKERR"),
                     Padding(1),
                     Flag("DACCVIOL"),
                     Flag("IACCVIOL"),
                     )

SCB_HFSR = 0xe000ed2c
scb_hfsr = BitStruct("scb_hfsr",
                     Flag("DEBUG_VT"),
                     Flag("FORCED"),
                     Padding(28),
                     Flag("VECTTBL"),
                     Padding(1),
                     )
SCB_MMFAR = 0xe000ed34
SCB_BFAR = 0xe000ed38

MPU_TYPER = 0xe000ed90
MPU_CR = 0xe000ed94
mpu_cr = BitStruct("mpu_cr",
                   Padding(29),
                   Flag("PRIVDEFENA"),
                   Flag("HFNMIENA"),
                   Flag("ENABLE"),
                   )

MPU_RNR = 0xe000ed98
mpu_rnr = BitStruct("mpu_rnr",
                    Padding(24),
                    BitField('REGION', 8))

MPU_RBAR = 0xe000ed9c
mpu_rbar = BitStruct("mpu_rbar",
                     BitField('ADDR', 27),
                     Flag('VALID'),
                     BitField('REGION', 4))

MPU_RASR = 0xe000eda0
mpu_rasr = BitStruct("mpu_rasr",
                     Padding(3),
                     Flag("XN"),
                     Padding(1),
                     #BitField("AP", 3),
                     Enum(BitField("AP", 3),
                          No_access = 0,
                          RW_No_access = 1,
                          RW_RO = 2,
                          RW = 3,
                          RO_No_access = 5,
                          RO = 6,
                          INV7 = 7),
                     Padding(2),
                     #BitField("TEX", 3), #Flag("S", 1), #Flag("C", 1), #Flag("B", 1),
                     Enum(BitField("TEXSCB", 6),
                          UNSET   =(0b000000),
                          FLASH_RAM   =(0b000010),
                          INTERNAL_RAM=(0b000110),
                          EXTERNAL_RAM=(0b000111),
                          PERIPHERIALS=(0b000101),),
                     BitField("SRD", 8),
                     Padding(2),
                     #BitField("SIZE", 5),
                     Enum(BitField("SIZE", 5),
                         unset   =(0b00000), invalid1=(0b00001), invalid2=(0b00010), invalid3=(0b00011),
                         _32B    =(0b00100), _64B    =(0b00101), _128B   =(0b00110), _256B   =(0b00111),
                         _512B   =(0b01000), _1KB    =(0b01001), _2KB    =(0b01010), _4KB    =(0b01011),
                         _8KB    =(0b01100), _16KB   =(0b01101), _32KB   =(0b01110), _64KB   =(0b01111),
                         _128KB  =(0b10000), _256KB  =(0b10001), _512KB  =(0b10010), _1MB    =(0b10011),
                         _2MB    =(0b10100), _4MB    =(0b10101), _8MB    =(0b10110), _16MB   =(0b10111),
                         _32MB   =(0b11000), _64MB   =(0b11001), _128MB  =(0b11010), _256MB  =(0b11011),
                         _512MB  =(0b11100), _1GB    =(0b11101), _2GB    =(0b11110), _4GB    =(0b11111),
                     ),
                     Flag("Enabled"))
