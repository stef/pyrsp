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

import os, time, sys
activate_this = os.path.dirname(__file__)+'/../env/bin/activate_this.py'
if os.path.exists(activate_this):
    execfile(activate_this, dict(__file__=activate_this))

import serial
from pyrsp.utils import hexdump, pack, unpack, unhex, switch_endian, split_by_n
from pyrsp.elf import ELF

class RSP(object):
    def __init__(self, port, elffile=None, verbose=False):
        """ read the elf file if given by elffile, connects to the
            debugging device specified by port, and initializes itself.
        """
        self.registers = self.arch['regs']
        self.__dict__['br'] = {}
        self.__dict__['verbose'] = verbose
        # open serial connection
        self.__dict__['port'] = serial.Serial(port, 115200, timeout=1)
        # parse elf for symbol table, entry point and work area
        self.__dict__['elf'] = ELF(elffile) if elffile else None
        if verbose and self.elf:
            print "work area: 0x%x" % self.elf.workarea
            print "entry: 0x%x" % self.elf.entry

        # check for signal from running target
        tmp = self.readpkt(timeout=1)
        if tmp: print tmp

        self.send('qSupported')
        feats = self.readpkt()
        if feats:
            self.feats = dict((ass.split('=') if '=' in ass else (ass,None) for ass in feats.split(';')))

        # attach
        self.connect()

    def connect(self):
        pass

    def send(self, data, retries=50):
        """ sends data via the RSP protocol to the device """
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
        #print 'sent', data

    def readpkt(self, timeout=0):
        """ blocks until it reads an RSP packet, and returns it's
            data"""
        c=None
        discards=[]
        if timeout>0:
            start = time.time()
        while(c!='$'):
            if c: discards.append(c)
            c=self.port.read()
            if timeout>0 and start+timeout < time.time():
                return
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
                #print "read", res
                return res

    def store(self, data, addr=None):
        """ stores data at addr if given otherwise at beginning of
            .text segment aka self.elf.workarea"""
        if addr==None:
            addr=self.elf.workarea
        for pkt in split_by_n(data, 400): # TODO should pktmaxsize, see todo in __init__
            pktlen = len(pkt)
            self.fetchOK('X%x,%x:%s' % (addr, pktlen, pkt))
            addr+=pktlen

    def __getslice__(self, i, j):
        return self.dump(j-i,i)

    def __setitem__(self, i,val):
        self.store(val,i)

    def __getattr__(self, name):
        if name not in self.__dict__ or not self.__dict__[name]:
            if name in self.regs.keys():
                return self.regs[name]
        if name in self.__dict__.keys():
            return self.__dict__[name]
        else:
            raise AttributeError, name

    def dump(self, size, addr = None):
        """ dumps data from addr if given otherwise at beginning of
            .text segment aka self.elf.workarea"""
        if addr==None:
            addr=self.elf.workarea
        rd = []
        i=0
        bsize = int(self.feats['PacketSize'])
        while(i<size):
            bsize = bsize if i+bsize<size else size - i
            self.send('m%x,%x' % (addr+i, bsize))
            pkt=self.readpkt()
            #print pkt
            rd.append(unhex(pkt))
            i+=bsize
        return ''.join(rd)

    def fetch(self,data):
        """ sends data and returns reply """
        self.send(data)
        return self.readpkt()

    def fetchOK(self,data,ok='OK'):
        """ sends data and expects success """
        res = self.fetch(data)
        if res!=ok: raise ValueError(res)

    def set_reg(self, reg, val):
        """ sets value of register reg to val on device """
        if isinstance(val, str):
            self.regs[reg]=val
        if isinstance(val, int):
            self.regs[reg]='%x' % val
        self.fetchOK("G%s" % ''.join([switch_endian(self.regs[r]) for r in self.registers]))

    def refresh_regs(self):
        """ loads and caches values of the registers on the device """
        self.send('g')
        if self.arch['endian']:
            self.regs=dict(zip(self.registers,(switch_endian(reg) for reg in split_by_n(self.readpkt(),self.arch['bitsize']>>2))))
        else:
            self.regs=dict(zip(self.registers,split_by_n(self.readpkt(),self.arch['bitsize']>>2)))

    def dump_regs(self):
        """ refreshes and dumps registers via stdout """
        self.refresh_regs()
        print ' '.join(["%s:%s" % (r, self.regs.get(r)) for r in self.registers])

    def get_thread_info(self):
        tid = None
        tmp = self.fetch('qC')
        if tmp.startswith("QC"):
            tid=tmp[2:].strip()
        extra = unhex(self.fetch('qThreadExtraInfo,%s' % tid))
        tids = []
        tmp = self.fetch('qfThreadInfo')
        while tmp != 'l':
            if not tmp.startswith('m'):
                raise ValueError('invalid qThreadInfo response')
            tids.extend(tmp[1:].split(','))
            tmp = self.fetch('qsThreadInfo')
        return (tid, extra, tids)

    def run(self, start=None):
        """ sets pc to start if given or to entry address from elf header,
            passes control to the device and handles breakpoints
        """
        if not start:
            entry = "%08x" % self.elf.entry
        else:
            entry = "%08x" % (self.elf.symbols[start] & ~1)
        if self.verbose: print "set new pc: @test (0x%s)" % entry,
        self.set_reg('pc', entry)
        if self.verbose: print 'OK'

        if self.verbose: print "continuing"
        sig = self.fetch('c')
        while sig == 'T05':
            self.handle_br()
            sig = self.fetch('c')

        print 'strange signal', sig
        src_line = self.get_src_line(int(self.regs['pc'],16) - 3)
        if src_line:
            print "0 %s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line'])
        src_line = self.get_src_line(int(self.regs['lr'],16) - 3)
        if src_line:
            print "1 %s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line'])

    def handle_br(self):
        """ dumps register on breakpoint/signal, continues if unknown,
            otherwise it calls the appropriate callback.
        """
        print
        self.dump_regs()
        if not self.regs['pc'] in self.br:
            print "unknown break point passed"
            self.dump_regs()
            return
        if self.verbose:
            print 'breakpoint hit:', self.br[self.regs['pc']]['sym']
        self.br[self.regs['pc']]['cb']()

    def set_br(self, sym, cb, quiet=False):
        """ sets a breakpoint at symbol sym, and install callback cb
            for it
        """
        addr = self.elf.symbols.get(sym)
        if not addr:
            print "unknown symbol: %s, ignoring request to set br" % sym
            return
        addr = "%08x" % (addr & ~1)
        if addr in self.br:
            print "warn: overwriting breakpoint at %s" % sym
            self.br[addr]={'sym': sym,
                           'cb': cb,
                           'old': self.br[addr]['old']}
        else:
            self.br[addr]={'sym': sym,
                           'cb': cb,
                           'old': unhex(self.fetch('m%s,2' % addr))}
        #self.fetch('Z0,%s,2' % addr)
        tmp = self.fetch('X%s,2:\xbe\xbe' % addr)
        if self.verbose and not quiet:
            print "set break: @%s (0x%s)" % (sym, addr), tmp

    def del_br(self, addr, quiet=False):
        """ deletes breakpoint at address addr """
        sym = self.br[addr]['sym']
        #self.fetch('z0,%s,2' % addr)
        tmp = self.fetch('X%s,2:%s' % (addr, self.br[addr]['old']))
        if self.verbose and not quiet: print "clear breakpoint: @%s (0x%s)" % (sym, addr), tmp
        del self.br[addr]

    def finish_cb(self):
        """ final breakpoint, if hit it deletes all breakpoints,
            continues running the cpu, and detaches from the debugging
            device
        """
        # clear all breaks
        for br in self.br.keys()[:]:
            self.del_br(br)
        if self.verbose:
            print "continuing and detaching"
        # leave in running state
        self.send('c')
        sys.exit(0)

    def get_src_line(self, addr):
        """ returns the source-code line associated with address addr
        """
        i = 0
        src_line = None
        while not src_line and i<1023:
            src_line = self.elf.src_map.get("%08x" % (addr - i))
            i+=2
        return src_line

    def step_over_br(self):
        sym = self.br[self.regs['pc']]['sym']
        cb  = self.br[self.regs['pc']]['cb']
        self.del_br(self.regs['pc'], quiet=True)
        sig = self.fetch('s')
        if sig == 'T05':
            self.set_br(sym, cb, quiet=True)
        else:
            print 'strange signal while stepi over br, abort'
            sys.exit(1)

    def dump_cb(self):
        """ rsp_dump callback, hit if rsp_dump is called. Outputs to
            stdout the source line, and a hexdump of the memory
            pointed by $r0 with a size of $r1 bytes. Then it resumes
            running.
        """
        src_line = self.get_src_line(int(self.regs['lr'],16) - 3)
        if src_line:
            print "%s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line'])

        res_size = int(self.regs['r1'],16)
        if res_size < 1024: # for sanity
            ptr = int(self.regs['r0'],16)
            res = unhex(self.fetch('m%x,%x' % (ptr, res_size)))
            print hexdump(res, ptr)

        self.step_over_br()

    def load(self, verify):
        """ loads binary belonging to elf to beginning of .text
            segment (alias self.elf.workarea), and if verify is set read
            it back and check if it matches with the uploaded binary.
        """
        if self.verbose: print 'load %s' % self.elf.name
        buf = self.elf.get_bin()
        self.store(buf)

        if verify:
            if self.verbose: print "verify test",
            if not self.dump(len(buf)) == buf:
                raise ValueError("uploaded binary failed to verify")
            if self.verbose: print 'OK'

    def call(self, start=None, finish='rsp_finish', dump='rsp_dump', verify=True):
        """
        1. Loads the '.bin' file given by self.elf into the device
           at the workarea (.text seg) of the device.
        2. Using the '.elf' file it sets a breakpoint on the function
           specified by rsp_finish and rsp_dump,
        3. and starts execution at the function specified by start or elf e_entry.
        4. After the breakpoint of rsp_dump is hit, r1 bytes are dumped
           from the buffer pointed to by r0.
        5. After the breakpoint of rsp_finish is hit, it removes all
           break points, and detaches
        """

        self.refresh_regs()
        self.load(verify)
        self.set_br(finish, self.finish_cb)
        self.set_br(dump, self.dump_cb)
        self.run(start)

    def test(self):
        # show current regs
        self.dump_regs()

        # test write
        self.fetchOK('X%08x,0' % self.elf.workarea)

        # reset workspace area
        self.store('\x00' * 2048)

        # verify workspace area empty
        if self.dump(2048) != '\x00' * 2048:
            raise ValueError('cannot erase work area')

class CortexM3(RSP):
    def __init__(self, *args,**kwargs):
        self.arch = {'regs': ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
                              "r9", "r10", "r11", "r12", "sp", "lr", "pc",
                              "xpsr", "msp", "psp", "special"],
                     'endian': True,
                     'bitsize': 32}
        super(CortexM3,self).__init__(*args, **kwargs)

    def get_thread_info(self):
        return

    def connect(self, id='1'):
        """ attaches to blackmagic jtag debugger in swd mode """
        # enable extended mode
        self.fetchOK('!')

        # setup registers TODO
        # registers should be parsed from the output of, see target.xml
        #self.fetch('qXfer:features:read:target.xml:0,3fb')
        #self.fetch('Xfer:features:read:target.xml:3cf,3fb')
        #self.fetch('qXfer:memory-map:read::0,3fb')
        #self.fetch('qXfer:memory-map:read::364,3fb')

        self.send('qRcmd,737764705f7363616e')
        pkt=self.readpkt()
        while pkt!='OK':
            if pkt[0]!='O':
                raise ValueError('not O: %s' % pkt)
            pkt=self.readpkt()
            if self.verbose:
                print unhex(pkt[1:-1])
        self.fetchOK('vAttach;%s' % id,'T05')

class AMD64(RSP):
    def __init__(self, *args,**kwargs):
        self.arch = {'regs': ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                              "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
                              "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
                              "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
                              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                              "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
                              "mxcsr",],
                     'endian': False,
                     'bitsize': 64}
        super(AMD64,self).__init__(*args, **kwargs)

class i386(RSP):
    # TODO gdb sends qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+
    def __init__(self, *args,**kwargs):
        self.arch = {'regs': ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                             "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
                             "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
                             "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
                             "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                             "mxcsr"],
                    'endian': False,
                    'bitsize': 32}
        super(i386,self).__init__(*args, **kwargs)

archmap={'amd64': AMD64, "i386": i386, "cortexm3": CortexM3}

def main():
    # parse arch from cmdline
    arch=i386
    for i, arg in enumerate(sys.argv):
        if arg in archmap:
            arch=archmap[arg]
            del sys.argv[i]
            break
    # argv[1] should be the file to the debugger device, e.g: /dev/ttyACM0
    # argv[2] can be the elf file
    if len(sys.argv)<2:
        print "%s [<%s>] <serial interface> [<elf file>]" % (sys.argv[0],
                                                             '|'.join(archmap.keys()))
        sys.exit(1)

    elffile=sys.argv[2] if len(sys.argv)>2 else None

    rsp = arch(sys.argv[1], elffile, verbose=True)

    if elffile:
        rsp.call()
    else:
        print hexdump(rsp.dump(2048, 0),0)
        rsp.dump_regs()
        print rsp.get_thread_info()
        rsp.send('c')

if __name__ == "__main__":
    main()
