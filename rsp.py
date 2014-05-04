#!/usr/bin/env python
#    This file is part of pyrsp

#    pyrsp is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    pyrsp is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with pyrsp  If not, see <http://www.gnu.org/licenses/>.

# (C) 2014 by Stefan Marsiske, <s@ctrlc.hu>

import os
activate_this = os.path.dirname(__file__)+'/env/bin/activate_this.py'
if os.path.exists(activate_this):
    execfile(activate_this, dict(__file__=activate_this))

import serial
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def pack(data):
    for a, b in [(x, chr(ord(x) ^ 0x20)) for x in ['}','*','#','$']]:
        data = data.replace(a,'}%s' % b)
    return "$%s#%02X" % (data, (sum(ord(c) for c in data) % 256))

def unpack(pkt):
    if pkt[0]!='$' or pkt[-3]!='#':
        raise ValueError('bad packet')
    if (sum(ord(c) for c in pkt[1:-3]) % 256) != int(pkt[-2:],16):
        raise ValueError('bad checksum')
    pkt = pkt[1:-3]
    return pkt

def unhex(data):
    return ''.join(chr(int(x,16)) for x in split_by_n(data,2))

def switch_endian(data):
    return ''.join(reversed(list(split_by_n( data ,2))))

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units.
       src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character"""
    while seq:
        yield seq[:n]
        seq = seq[n:]

class RSP:
    def __init__(self, port, file_prefix, verbose=False):
        self.br = {}
        self.verbose = verbose
        # open serial connection
        self.port = serial.Serial(port, 115200, timeout=1)
        # parse elf for symbol table, entry point and work area
        self.read_elf('%s.elf' % file_prefix)
        if verbose:
            print "work area: 0x%x" % self.workarea
            print "entry: 0x%x" % self.entry

        # setup registers
        self.registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr", "msp", "psp", "special"]
        # registers should be parsed from the output of
        #self.fetch('qXfer:features:read:target.xml:0,3fb')
        #self.fetch('Xfer:features:read:target.xml:3cf,3fb')
        #self.fetch('qXfer:memory-map:read::0,3fb')
        #self.fetch('qXfer:memory-map:read::364,3fb')

        # read initial OK
        pkt = self.readpkt()
        if pkt!='OK': raise ValueError(repr(pkt))

        # read out maxpacketsize and ignore it for the time being /o\
        self.send('qSupported')
        self.feats = [ass.split('=') for ass in self.readpkt().split(';')]

        # enable extended-mode
        self.fetchOK('!')

        # attach
        self.attach()

        # test write
        self.fetchOK('X%08x,0' % self.workarea)

        # reset workspace area
        self.store('\x00' * 2048)

        # verify workspace area empty
        if self.dump(2048) != '\x00' * 2048:
            raise ValueError('cannot erase work area')

    def send(self, data, retries=50):
        self.port.write(pack(data))
        res = None
        while not res:
            res = self.port.read()
        discards = []
        while res!='+' and retries>0:
            discards.append(res)
            self.port.write(pack(data))
            retries-=1
            res = self.port.read()
        if len(discards)>0: print 'send discards', discards
        if retries==0:
            raise ValueError("retry fail")

    def readpkt(self):
        c=None
        discards=[]
        while(c!='$'):
            if c: discards.append(c)
            c=self.port.read()
        if len(discards)>0: print 'discards', discards
        res=[c]
        while True:
            res.append(self.port.read())
            if res[-1]=='#' and res[-2]!="'":
                res.append(self.port.read())
                res.append(self.port.read())
                try:
                    res=unpack(''.join(res))
                except:
                    self.port.write('-')
                    res=[]
                    continue
                self.port.write('+')
                return res

    def store(self, data, addr=None):
        if addr==None:
            addr=self.workarea
        for pkt in split_by_n(data, 400):
            pktlen = len(pkt)
            self.fetchOK('X%x,%x:%s' % (addr, pktlen, pkt))
            addr+=pktlen

    def dump(self, size, addr = None):
        if addr==None:
            addr=self.workarea
        rd = []
        i=0
        bsize = 256
        while(i<size):
            bsize = bsize if i+bsize<size else size - i
            self.send('m%x,%x' % (addr+i, bsize))
            pkt=self.readpkt()
            #print pkt
            rd.append(unhex(pkt))
            i+=bsize
        return ''.join(rd)

    def fetch(self,data):
        self.send(data)
        return self.readpkt()

    def fetchOK(self,data,ok='OK'):
        res = self.fetch(data)
        if res!=ok: raise ValueError(res)

    def set_reg(self, reg, val):
        if isinstance(val, str):
            self.regs[reg]=val
        if isinstance(val, int):
            self.regs[reg]='%x' % val
        self.fetchOK("G%s" % ''.join([switch_endian(self.regs[r]) for r in self.registers]))

    def refresh_regs(self):
        self.send('g')
        self.regs=dict(zip(self.registers,(switch_endian(reg) for reg in split_by_n(self.readpkt(),8))))

    def dump_regs(self):
        self.refresh_regs()
        print ' '.join(["%8s" % r for r in self.registers[:-1]])
        print ' '.join(["%s" % self.regs[r] for r in self.registers[:-1]])

    def attach(self, id='1'):
        self.send('qRcmd,737764705f7363616e')
        pkt=self.readpkt()
        while pkt!='OK':
            if pkt[0]!='O':
                raise ValueError('not O')
            pkt=self.readpkt()
            if self.verbose:
                print unhex(pkt[1:-1])
        self.fetchOK('vAttach;%s' % id,'T05')

    def run(self, start=None):
        if not start:
            entry = self.entry
        else:
            entry = "%08x" % (self.symbols[start] & ~1)
        if self.verbose: print "set new pc: @test (0x%s)" % entry,
        self.set_reg('pc', entry)
        if self.verbose: print 'OK'

        if self.verbose: print "continuing"
        sig = self.fetch('c')
        while sig == 'T05':
            self.handle_br()
            sig = self.fetch('c')
        print 'strange signal', sig

    def handle_br(self):
        self.refresh_regs()
        if not self.regs['pc'] in self.br:
            print "unknown break point passed"
            return
        if self.verbose:
            print 'breakpoint hit:', self.br[self.regs['pc']]['sym']
        self.dump_regs()
        self.br[self.regs['pc']]['cb']()

    def set_br(self, sym, cb, quiet=False):
        addr = "%08x" % (self.symbols[sym]& ~1)
        if addr in self.br: print "warn: overwriting breakpoint at %s" % sym
        self.br[addr]={'sym': sym,
                       'cb': cb,
                       'old': unhex(self.fetch('m%s,2' % addr))}
        #self.fetch('Z0,%s,2' % addr)
        tmp = self.fetch('X%s,2:\xbe\xbe' % addr)
        if self.verbose and not quiet:
            print "set break: @%s (0x%s)" % (sym, addr), tmp

    def del_br(self, addr, quiet=False):
        sym = self.br[addr]['sym']
        #self.fetch('z0,%s,2' % addr)
        tmp = self.fetch('X%s,2:%s' % (addr, self.br[addr]['old']))
        if self.verbose and not quiet: print "clear breakpoint: @%s (0x%s)" % (sym, addr), tmp
        del self.br[addr]

    def finish_cb(self):
        # clear all breaks
        for br in self.br.keys()[:]:
            self.del_br(br)
        # leave in running state
        if self.verbose:
            print "continuing and detaching"
        self.send('c')
        sys.exit(0)

    def dump_cb(self):
        sym = self.br[self.regs['pc']]['sym']
        res_size = int(self.regs['r1'],16)
        if res_size < 1024: # for sanity
            ptr = int(self.regs['r0'],16)
            res = unhex(self.fetch('m%x,%x' % (ptr, res_size)))
            print repr(res)
            print [hex(ord(x)) for x in res]

        self.del_br(self.regs['pc'], quiet=True)
        sig = self.fetch('s')
        if sig == 'T05':
            self.set_br(sym, self.dump_cb, quiet=True)
        else:
            print 'strange signal while stepi over br, abort'
            sys.exit(1)

    def call(self, file_prefix, start=None, finish='finish', results='result', res_size=10, verify=True):
        """
        1. Loads the '.bin' file given by file_prefix into the device
           at the workarea of the device.
        2. If verify is set, the workarea is read out and compared to
           the original '.bin' file.
        3. Using the '.elf' file it sets a breakpoint on the function
           specified by finish,
        4. and starts execution at the function specified by start.
        5. After the breakpoint of finish is hit, it removes it,
        6. and if the symbol specified in results exists, it returns
           the memory pointed by it limited by the res_size parameter.
        """

        if self.verbose: print 'load %s.bin' % file_prefix
        with open('%s.bin' % file_prefix,'r') as fd:
            buf = fd.read()
            self.store(buf)

        if verify:
            if self.verbose: print "verify test",
            if not self.dump(len(buf)) == buf:
                raise ValueError("uploaded binary failed to verify")
            if self.verbose: print 'OK'

        self.set_br(finish, self.finish_cb)
        self.set_br('dump', self.dump_cb)
        self.run(start)

    def read_elf(self, fname):
        with open(fname,'r') as stream:
            elffile = ELFFile(stream)

            # get entry point
            self.entry = elffile.header.e_entry

            # get text seg address
            section = elffile.get_section_by_name(b'.text')
            if not section:
                raise ValueError('No symbol table found. Perhaps this ELF has been stripped?')
            self.workarea = section.header['sh_addr']

            # init symbols
            section = elffile.get_section_by_name(b'.symtab')
            if not section:
                raise ValueError('No symbol table found. Perhaps this ELF has been stripped?')

            res = {}
            if isinstance(section, SymbolTableSection):
                for i in xrange(section.num_symbols()):
                    res[section.get_symbol(i).name]=(section.get_symbol(i).entry.st_value)
            self.symbols = res

if __name__ == "__main__":
    import sys
    # argv[1] should be the file to the debugger device, e.g: /dev/ttyACM0
    rsp = RSP(sys.argv[1], 'test', verbose=True)
    rsp.dump_regs()
    res = rsp.call('test')
