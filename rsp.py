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

import sys, serial, elf

def encode(data):
    for a, b in [(x, chr(ord(x) ^ 0x20)) for x in ['}','*','#','$']]:
        data = data.replace(a,'}%s' % b)
    return "$%s#%02X" % (data, (sum(ord(c) for c in data) % 256))

def decode(pkt):
    if pkt[0]!='$' or pkt[-3]!='#':
        raise ValueError('bad packet')
    if (sum(ord(c) for c in pkt[1:-3]) % 256) != int(pkt[-2:],16):
        raise ValueError('bad checksum')
    pkt = pkt[1:-3]
    return pkt

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units.
       src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character"""
    while seq:
        yield seq[:n]
        seq = seq[n:]

class RSP:
    def __init__(self, port):
        self.port = serial.Serial(port, 115200, timeout=1)
        self.registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr", "msp", "psp", "special"]
        pkt = self.readpkt()
        if pkt!='OK': raise ValueError(repr(pkt))
        self.send('qSupported')
        self.feats = [ass.split('=') for ass in self.readpkt().split(';')]

        self.fetchOK('!') # enable extended-mode

        # attach
        self.attach()

        #rsp.fetch('qXfer:features:read:target.xml:0,3fb')
        #rsp.fetch('Xfer:features:read:target.xml:3cf,3fb')
        #self.fetch('qXfer:memory-map:read::0,3fb')
        #self.fetch('qXfer:memory-map:read::364,3fb')

        # test write
        self.fetchOK('X20019000,0')

        # reset workspace area
        self.store('\x00' * 2048)

        # verify workspace area empty
        if self.dump(2048) != '\x00' * 2048:
            raise ValueError('cannot erase work area')

    def send(self, data, retries=50):
        self.port.write(encode(data))
        res = None
        while not res:
            res = self.port.read()
        discards = []
        while res!='+' and retries>0:
            discards.append(res)
            self.port.write(encode(data))
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
                    res=decode(''.join(res))
                except:
                    self.port.write('-')
                    res=[]
                    continue
                self.port.write('+')
                return res

    def store(self, data, addr=0x20019000):
        for pkt in split_by_n(data, 400):
            pktlen = len(pkt)
            self.fetchOK('X%x,%x:%s' % (addr, pktlen, pkt))
            addr+=pktlen

    def dump(self, size, addr = 0x20019000):
        rd = []
        i=0
        bsize = 256
        while(i<size):
            bsize = bsize if i+bsize<size else size - i
            self.send('m%x,%x' % (addr+i, bsize))
            pkt=self.readpkt()
            #print pkt
            rd.append(''.join(chr(int(x,16)) for x in split_by_n(pkt,2)))
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
        self.fetchOK("G%s" % ''.join([''.join(reversed(list(split_by_n(self.regs[r],2)))) for r in self.registers]))

    def refresh_regs(self):
        self.send('g')
        self.regs=dict(zip(self.registers,(''.join(reversed(list(split_by_n(reg,2)))) for reg in split_by_n(self.readpkt(),8))))

    def dump_regs(self):
        self.refresh_regs()
        for r in self.registers:
            print "%4s 0x%s" % (r, self.regs[r])

    def attach(self, id='1', verbose=False):
        self.send('qRcmd,737764705f7363616e')
        pkt=self.readpkt()
        while pkt!='OK':
            if pkt[0]!='O':
                raise ValueError('not O')
            pkt=self.readpkt()
            if verbose:
                print ''.join(chr(int(x,16)) for x in split_by_n(pkt[1:-1],2))
        self.fetchOK('vAttach;%s' % id,'T05')

# example loads a test.bin to 0x20019000 and hands over control to the
# function `test', needs test.bin and test.elf to work.
# argv[1] should be the file to the debugger device, e.g: /dev/ttyACM0

rsp = RSP(sys.argv[1])
rsp.dump_regs()

# load test.bin
print 'load test'
with open('test.bin','r') as fd:
    buf = fd.read()
    rsp.store(buf)

print "verify test"
rd = rsp.dump(len(buf))
print rd == buf

#########################

entry = "%08x" % (elf.get_symbols('test.elf')['test'] & ~1)
print "set new pc: @test (0x%s)" % entry
rsp.set_reg('pc', entry)

#print "stepping"
#print rsp.fetch('s')

#rsp.dump_regs()

print "continuing"
rsp.send('c')
