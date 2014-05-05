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
    """ formats data into a RSP packet """
    for a, b in [(x, chr(ord(x) ^ 0x20)) for x in ['}','*','#','$']]:
        data = data.replace(a,'}%s' % b)
    return "$%s#%02X" % (data, (sum(ord(c) for c in data) % 256))

def unpack(pkt):
    """ unpacks an RSP packet, returns the data"""
    if pkt[0]!='$' or pkt[-3]!='#':
        raise ValueError('bad packet')
    if (sum(ord(c) for c in pkt[1:-3]) % 256) != int(pkt[-2:],16):
        raise ValueError('bad checksum')
    pkt = pkt[1:-3]
    return pkt

def unhex(data):
    """ takes a hex encoded string and returns the binary representation """
    return ''.join(chr(int(x,16)) for x in split_by_n(data,2))

def switch_endian(data):
    """ byte-wise reverses a hex encoded string """
    return ''.join(reversed(list(split_by_n( data ,2))))

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units.
       src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character"""
    while seq:
        yield seq[:n]
        seq = seq[n:]

def hexdump(data):
    """ returns data formatted as a hexdump """
    return "\t%s" % '\n\t'.join(["%s %s" % (' '.join([''.join(["%02x" % ord(c) for c in word])
                                                      for word in split_by_n(line,8)]),
                                            ''.join([c if c.isalnum() else '.' for c in line]))
                                 for line in split_by_n(data,32)])

class FCache():
    """ helper class to read out the source code lines
        from the debug section of an elf file """
    def __init__(self):
        self.fd = None
        self.name = None

    def get_src_lines(self, fname, start, end = None):
        """ returns the lines indexed from start to end of the file
            indicated by fname"""
        if not self.name or self.name != fname:
            if self.name:
                self.fd.close()
            self.fd = open(fname,'r')
            self.name = fname

        self.fd.seek(0)
        line_ptr=0
        while line_ptr < start-1:
            self.fd.readline()
            line_ptr+=1
        if end and end>start:
            res = []
            while line_ptr<end:
                res.append(self.fd.readline())
                line_ptr+=1
            return ''.join(res).strip()
        else:
            return self.fd.readline().strip()
fcache = FCache()

def get_src_map(elffile):
    """ builds a dictionary of the DWARF information, used to populate
        RSP.src_map

        returns a dictionary with either the address as key, or
        filename:lineno the values are respectively {addr, file,
        lineno, line} and {addr, line}
    """

    src_map = {}
    if not elffile.has_dwarf_info():
        raise ValueError("No DWARF info found")
    _dwarfinfo = elffile.get_dwarf_info()

    for cu in _dwarfinfo.iter_CUs():
        lineprogram = _dwarfinfo.line_program_for_CU(cu)

        cu_filename = lineprogram['file_entry'][0].name
        if len(lineprogram['include_directory']) > 0:
            dir_index = lineprogram['file_entry'][0].dir_index
            if dir_index > 0:
                dir = lineprogram['include_directory'][dir_index - 1]
            else:
                dir = '.'
            cu_filename = '%s/%s' % (dir, cu_filename)

        for entry in lineprogram.get_entries():
            state = entry.state
            if state:
                fname = lineprogram['file_entry'][state.file - 1].name
                line = fcache.get_src_lines(fname, state.line)
                src_map["%08x" % state.address] = {'file': fname, 'lineno': state.line, 'line': line}
                try:
                    src_map["%s:%s" % (fname, state.line)].append({'addr': "%08x" % state.address, 'line': line})
                except KeyError:
                    src_map["%s:%s" % (fname, state.line)]= [{'addr': "%08x" % state.address, 'line': line}]
    return src_map

class RSP:
    def __init__(self, port, file_prefix=None, verbose=False):
        """ read the elf file if given by file_prefix, connects to the
            debugging device specified by port, and initializes itself.
        """
        self.br = {}
        self.verbose = verbose
        self.file_prefix = file_prefix
        # open serial connection
        self.port = serial.Serial(port, 115200, timeout=1)
        # parse elf for symbol table, entry point and work area
        self.read_elf('%s.elf' % self.file_prefix)
        if verbose:
            print "work area: 0x%x" % self.workarea
            print "entry: 0x%x" % self.entry

        # setup registers TODO
        self.registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr", "msp", "psp", "special"]
        # registers should be parsed from the output of, see target.xml
        #self.fetch('qXfer:features:read:target.xml:0,3fb')
        #self.fetch('Xfer:features:read:target.xml:3cf,3fb')
        #self.fetch('qXfer:memory-map:read::0,3fb')
        #self.fetch('qXfer:memory-map:read::364,3fb')

        # read initial OK
        pkt = self.readpkt()
        if pkt!='OK': raise ValueError(repr(pkt))

        # read out maxpacketsize and ignore it for the time being /o\ TODO
        self.send('qSupported')
        self.feats = [ass.split('=') for ass in self.readpkt().split(';')]

        # enable extended-mode
        self.fetchOK('!')

        # attach
        self.attach()

        # show current regs
        self.dump_regs()

        # test write
        self.fetchOK('X%08x,0' % self.workarea)

        # reset workspace area
        self.store('\x00' * 2048)

        # verify workspace area empty
        if self.dump(2048) != '\x00' * 2048:
            raise ValueError('cannot erase work area')

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

    def readpkt(self):
        """ blocks until it reads an RSP packet, and returns it's
            data"""
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
        """ stores data at addr if given otherwise at beginning of
            .text segment aka self.workarea"""
        if addr==None:
            addr=self.workarea
        for pkt in split_by_n(data, 400): # TODO should pktmaxsize, see todo in __init__
            pktlen = len(pkt)
            self.fetchOK('X%x,%x:%s' % (addr, pktlen, pkt))
            addr+=pktlen

    def dump(self, size, addr = None):
        """ dumps data from addr if given otherwise at beginning of
            .text segment aka self.workarea"""
        if addr==None:
            addr=self.workarea
        rd = []
        i=0
        bsize = 256 # TODO should pktmaxsize, see todo in __init__
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
        self.regs=dict(zip(self.registers,(switch_endian(reg) for reg in split_by_n(self.readpkt(),8))))

    def dump_regs(self):
        """ refreshes and dumps registers via stdout """
        self.refresh_regs()
        print ' '.join(["%8s" % r for r in self.registers[:-1]])
        print ' '.join(["%s" % self.regs[r] for r in self.registers[:-1]])

    def attach(self, id='1'):
        """ attaches to blackmagic jtag debugger in swd mode """
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
        """ sets pc to start if given or to entry address from elf header,
            passes control to the device and handles breakpoints
        """
        if not start:
            entry = "%08x" % self.entry
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
        addr = self.symbols.get(sym)
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
            src_line = self.src_map.get("%08x" % (addr - i))
            i+=2
        return src_line

    def dump_cb(self):
        """ rsp_dump callback, hit if rsp_dump is called. Outputs to
            stdout the source line, and a hexdump of the memory
            pointed by $r0 with a size of $r1 bytes. Then it resumes
            running.
        """
        src_line = self.get_src_line(int(self.regs['lr'],16) - 3)
        if src_line:
            print "%s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line'])

        sym = self.br[self.regs['pc']]['sym']
        res_size = int(self.regs['r1'],16)
        if res_size < 1024: # for sanity
            ptr = int(self.regs['r0'],16)
            res = unhex(self.fetch('m%x,%x' % (ptr, res_size)))
            print hexdump(res)

        self.del_br(self.regs['pc'], quiet=True)
        sig = self.fetch('s')
        if sig == 'T05':
            self.set_br(sym, self.dump_cb, quiet=True)
        else:
            print 'strange signal while stepi over br, abort'
            sys.exit(1)

    def load(self, verify):
        """ loads binary belonging to elf to beginning of .text
            segment (alias self.workarea), and if verify is set read
            it back and check if it matches with the uploaded binary.
        """
        if self.verbose: print 'load %s.bin' % self.file_prefix
        with open('%s.bin' % self.file_prefix,'r') as fd:
            buf = fd.read()
            self.store(buf)

        if verify:
            if self.verbose: print "verify test",
            if not self.dump(len(buf)) == buf:
                raise ValueError("uploaded binary failed to verify")
            if self.verbose: print 'OK'

    def call(self, start=None, finish='rsp_finish', dump='rsp_dump', verify=True):
        """
        1. Loads the '.bin' file given by self.file_prefix into the device
           at the workarea (.text seg) of the device.
        2. Using the '.elf' file it sets a breakpoint on the function
           specified by rsp_finish and rsp_dump,
        3. and starts execution at the function specified by start or elf e_entry.
        4. After the breakpoint of rsp_dump is hit, r1 bytes are dumped
           from the buffer pointed to by r0.
        5. After the breakpoint of rsp_finish is hit, it removes all
           break points, and detaches
        """

        self.load(verify)
        self.set_br(finish, self.finish_cb)
        self.set_br(dump, self.dump_cb)
        self.run(start)

    def read_elf(self, fname):
        """ reads out the entry point, the .text segment addres, the
            symbol table, and the debugging information from the elf
            header.
        """
        with open(fname,'r') as stream:
            elffile = ELFFile(stream)

            # get entry point
            self.entry = elffile.header.e_entry

            # get text seg address
            section = elffile.get_section_by_name(b'.text')
            if not section:
                raise ValueError('No text segment found.')
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

            self.src_map = get_src_map(elffile)

if __name__ == "__main__":
    import sys
    # argv[1] should be the file to the debugger device, e.g: /dev/ttyACM0
    rsp = RSP(sys.argv[1], sys.argv[2], verbose=True)
    res = rsp.call()
