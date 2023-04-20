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

import os, time, sys, struct, socket
activate_this = os.path.dirname(__file__)+'/../env/bin/activate_this.py'
if os.path.exists(activate_this):
    from six import PY3
    if PY3: # goddamn py3 has no execfile.
        def execfile(fpath, gvars):
            with open(fpath) as f:
                code = compile(f.read(), fpath, 'exec')
                exec(code, gvars)
    execfile(activate_this, dict(__file__=activate_this))

import serial
from pyrsp.utils import (hexdump, pack, unpack, unhex, switch_endian,
    split_by_n, rsp_decode, stop_reply, stop_event, s)
from pyrsp.elf import ELF
from binascii import hexlify
from six import integer_types
from six.moves import range

def Debugger(*args, **kwargs):
    if os.path.exists(args[0]):
        return BlackMagic(*args,**kwargs)
    return STlink2(*args, **kwargs)

class BlackMagic(object):
    def __init__(self, port):
        self.__dict__['port'] = serial.Serial(port, 115200, timeout=1)

    def setup(self, rsp):
        rsp.send(b'qRcmd,737764705f7363616e')
        pkt=rsp.readpkt()
        while pkt!=b'OK':
            if pkt[:1]!=b'O':
                raise ValueError('not O: %s' % pkt)
            if rsp.verbose:
                print(unhex(pkt[1:-1]))
            pkt=rsp.readpkt()
        rsp.fetchOK(b'vAttach;1',b'T05')

    def write(self, data):
        return self.port.write(data)

    def read(self, size=1):
        return self.port.read(size)

    def close(self, rsp):
        rsp.fetchOK(b'D')
        self.port.close()

class STlink2(object):
    def __init__(self, port):
        self.__dict__['port'] = socket.socket( socket.AF_INET,socket.SOCK_STREAM)
        self.port.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port.settimeout(0.1)
        address = port.split(':')
        self.port.connect(('localhost' if len(address) == 1 else address[0],int(address[-1])))
        self._buf = b""

    def setup(self, rsp):
        pass

    def write(self, data):
        i = 0
        while(i<len(data)):
            i += self.port.send(data[i:])
        return i

    def read(self):
        buf = self._buf
        if not buf:
            try:
                buf = self.port.recv(4096)
            except socket.timeout:
                pass
            else:
                if buf == b'':
                    # according to https://docs.python.org/3/howto/sockets.html
                    raise RuntimeError("socket connection broken")

        ret = buf[:1]
        self._buf = buf[1:]
        return ret

    def close(self):
        self.port.close()

class RSP(object):
    def __init__(self, port, elffile=None, verbose=False, noack=False,
                 noshell=False):
        """ read the elf file if given by elffile, connects to the
            debugging device specified by port, and initializes itself.
        """
        # Initially packet acknowledgment is enabled.
        # https://sourceware.org/gdb/onlinedocs/gdb/Packet-Acknowledgment.html
        self.ack = True
        self.registers = self.arch['regs']
        self.maxsize_g_packet = 0
        self.reg_fmt = b"%%0%ux" % (self.arch['bitsize'] >> 2)
        self.__dict__['br'] = {}
        self.__dict__['verbose'] = verbose
        # open serial connection
        self.__dict__['port'] = Debugger(port) #serial.Serial(port, 115200, timeout=1)
        # parse elf for symbol table, entry point and work area
        self.__dict__['elf'] = ELF(elffile) if elffile else None
        if verbose and self.elf:
            print("work area: 0x%x" % self.elf.workarea)
            print("entry: 0x%x" % self.elf.entry)

        # check for signal from running target
        tmp = self.readpkt(timeout=0.1)
        if tmp and verbose: print('helo %s' % s(tmp))

        #self.port.write(pack('qSupported:multiprocess+;qRelocInsn+'))
        self._get_feats()

        # By default, use Z/z packets to manipulate breakpoints
        self.z_breaks = True

        self._thread = None

        # select all threads initially
        self.thread = b"0"

        if noack and b"QStartNoAckMode+" in self.feats:
            self.fetchOK(b"QStartNoAckMode")
            self.ack = False
            self.read_ack = lambda *_, **__ : None

        # replace deprecated resumption commands with new vCont analogues
        # https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#vCont-packet
        if b"vContSupported+" in self.feats:
            actions = self.fetch(b"vCont?").split(b';') # vCont[;action...]
            if b"c" in actions:
                self.cont = self.vContc
                self.cont_all = self.vContc_all
            if b"s" in actions:
                self.step = self.vConts

        if noshell and b"QStartupWithShell+" in self.feats:
            # extended mode is required
            self.fetchOK(b"!")
            self.fetchOK(b"QStartupWithShell:0")
            self.noshell = True
        else:
            self.noshell = False

        # attach
        self.connect()

    @property
    def thread(self):
        return self._thread

    @thread.setter
    def thread(self, pid_tid):
        if self._thread != pid_tid:
            self.fetchOK(b"Hg" + pid_tid)
            self._thread = pid_tid

    def connect(self):
        pass

    def read_ack(self, retries=50):
        res = None
        while not res:
            res = self.port.read()
        discards = []
        while res != b'+' and retries > 0:
            discards.append(s(res))
            retries -= 1
            res = self.port.read()
        if len(discards) > 0 and self.verbose:
            print('read_ack discards %s' % discards)
        if retries == 0:
            raise ValueError("retry fail")

    def send(self, data, retries=50):
        """ sends data via the RSP protocol to the device """
        self.port.write(pack(data))
        self.read_ack(retries)
        #print('sent %s' % data)

    def readpkt(self, timeout=0):
        """ blocks until it reads an RSP packet, and returns it's
            data"""
        c=b""
        discards=[]
        if timeout>0:
            start = time.time()
        while(c!=b'$'):
            if c: discards.append(s(c))
            c=self.port.read()
            if timeout>0 and start+timeout < time.time():
                return
        if len(discards)>0 and self.verbose: print('discards %s' % discards)
        res=c

        while True:
            res += self.port.read()
            if res[-1:]==b'#':
                res += self.port.read() + self.port.read()
                if self.ack:
                    try:
                        res = unpack(res)
                    except:
                        self.port.write(b'-')
                        res = b''
                        continue
                    self.port.write(b'+')
                else:
                    # Do not even check packages in NoAck mode.
                    # If a user relies on the connection robustness then we
                    # should provide as fast operation as we can.
                    res = res[1:-3]
                #print("read %s" % res)
                return res

    def store(self, data, addr=None):
        """ stores data at addr if given otherwise at beginning of
            .text segment aka self.elf.workarea"""
        if addr==None:
            addr=self.elf.workarea
        for pkt in split_by_n(hexlify(data), self.get_packet_size() - 20):
            pktlen = len(pkt)//2
            self.fetchOK(b'M%x,%x:%s' % (addr, pktlen, pkt))
            addr+=pktlen

    def __getitem__(self, s):
        if isinstance(s, slice):
            return self.dump(s.stop - s.start, s.start)
        else:
            # assume that `s` has type compatible with `dump` method
            return self.dump(1, s)

    def __setitem__(self, i,val):
        self.store(val,i)

    def _get_feats(self):
        if self.ack:
            self.port.write(pack(b'+'))

        tmp = self.readpkt(timeout=1)
        if tmp and self.verbose: print('helo %s' % s(tmp))

        self.send(b'qSupported:swbreak+;vContSupported+')
        feats = self.readpkt()
        if feats:
            self.feats = dict((ass.split(b'=') if b'=' in ass else (ass,None) for ass in feats.split(b';')))

    def get_packet_size(self):
        '''Report the maximum packet size.

        Uses the PacketSize feature if it is available otherwise we use a
        similar heuristic to gdb. Namely we adopt a hardcoded default but
        if we observe larger g packets we increase that default.
        '''
        if self.feats and b'PacketSize' in self.feats:
            return int(self.feats[b'PacketSize'], 16)

        return max(self.maxsize_g_packet, 400-1);

    def __getattr__(self, name):
        if name not in self.__dict__ or not self.__dict__[name]:
            if name=='regs':
                self.refresh_regs()
                return self.__dict__[name]
            if name in self.regs.keys():
                return self.regs[name]
        if name in self.__dict__.keys():
            return self.__dict__[name]
        else:
            if name=='feats':
                self._get_feats()
                if name in self.__dict__.keys():
                    return self.__dict__[name]
                else:
                    return {}
            raise AttributeError(name)

    def dump(self, size, addr = None):
        """ dumps data from addr if given otherwise at beginning of
            .text segment aka self.elf.workarea"""
        if addr==None:
            addr=self.elf.workarea
        rd = b''
        end = addr + size
        bsize = self.get_packet_size() // 2
        while addr < end:
            bsize = bsize if addr + bsize < end else end - addr
            #print('m%x,%x' % (addr, bsize))
            pkt = self.fetch(b'm%x,%x' % (addr, bsize))
            if len(pkt) & 1 and pkt[:1] == b'E':
                # There is an assumption that stub only uses 'e' for data
                # hexadecimal representation and 'E' is only used for errors.
                # However, no confirmation has been found in the protocol
                # definition. But, according to the protocol error message
                # data length is always odd (i.e. Exx).
                raise RuntimeError("Reading %u bytes at 0x%x failed: %s " % (
                    bsize, addr, s(pkt)
                ))
            rd += unhex(rsp_decode(pkt))
            addr += bsize
            #print("%s %s pkt %s" % (addr, bsize, pkt))
        return rd

    def fetch(self,data):
        """ sends data and returns reply """
        self.send(data)
        return self.readpkt()

    def fetchOK(self,data,ok=b'OK'):
        """ sends data and expects success """
        res = self.fetch(data)
        if res!=ok: raise ValueError(res)

    def vContc_all(self):
        return self.fetch(b"vCont;c")

    def vConts_all(self):
        return self.fetch(b"vCont;s")

    def vContc(self):
        return self.fetch(b"vCont;c:" + self._thread)

    def vConts(self):
        return self.fetch(b"vCont;s:" + self._thread)

    def c(self):
        return self.fetch(b"c")

    def s(self):
        return self.fetch(b"s")

    # They will be replaced with vCont variants if supported by the stub.
    step = s
    cont = c
    # 'c' packet is deprecated for multi-threading support.
    # But cont_all is same as cont for a single-threaded process.
    cont_all = c

    def set_reg(self, reg, val):
        """ sets value of register reg to val on device """
        if isinstance(val, str):
            self.regs[reg]=val
        if isinstance(val, integer_types):
            self.regs[reg]=self.reg_fmt % val
        self.fetchOK(b"G%s" % b''.join([switch_endian(self.regs[r]) for r in self.registers if r in self.regs]))

    def refresh_regs(self):
        """ loads and caches values of the registers on the device """
        self.send(b'g')
        enc_reg_blob = self.readpkt()
        reg_blob = rsp_decode(enc_reg_blob)
        raw_regs = split_by_n(reg_blob, self.arch['bitsize']>>2)
        if self.arch['endian']:
            raw_regs = iter(switch_endian(reg) for reg in raw_regs)
        self.regs = dict(zip(self.registers, raw_regs))

        pktsz = len(enc_reg_blob) + 4   # 4 adds back the header and checksum
        if pktsz > self.maxsize_g_packet:
            self.maxsize_g_packet = pktsz

    def dump_regs(self):
        """ refreshes and dumps registers via stdout """
        self.refresh_regs()
        print(' '.join(["%s:%s" % (r, s(self.regs.get(r))) for r in self.registers]))

    prev_regs={}
    def lazy_dump_regs(self):
        """ refreshes and dumps registers via stdout """
        self.refresh_regs()
        print('[r]' + ' '.join(["%s:%s" % (r, s(self.regs.get(r))) for r in self.registers if self.regs.get(r)!=self.prev_regs.get(r)]))
        self.prev_regs=self.regs

    def get_thread_info(self):
        tid = None
        tmp = self.fetch(b'qC')
        if tmp.startswith(b"QC"):
            tid=tmp[2:].strip()
        extra = unhex(self.fetch(b'qThreadExtraInfo,%s' % tid))
        tids = []
        tmp = self.fetch(b'qfThreadInfo')
        while tmp != b'l':
            if not tmp.startswith(b'm'):
                raise ValueError('invalid qThreadInfo response')
            tids.extend(tmp[1:].split(b','))
            tmp = self.fetch(b'qsThreadInfo')
        return (tid, extra, tids)

    def run(self, start=None, setpc=True):
        """ sets pc to start if given or to entry address from elf header,
            passes control to the device and handles breakpoints
        """
        if setpc:
            if not start:
                entry_addr = self.elf.entry
            else:
                entry_addr = self.elf.symbols[start]
            if isinstance(self, CortexM3):
                entry_addr &= ~1
            entry = self.reg_fmt % entry_addr
            if self.verbose: print("set new pc: @test (0x%s)" % s(entry))
            self.set_reg(self.pc_reg, entry)
            if self.verbose: print('OK')

        if self.verbose: print("continuing")
        self.exit = False
        kind, sig, data = stop_reply(self.cont_all())
        while True:
            if kind == b'O':
                print(unhexlify(data).decode())
                kind, sig, data = stop_reply(self.readpkt())
            elif kind in (b'T', b'S') and sig == 5:
                # Update current thread for a breakpoint handler.
                event = stop_event(data)
                self.stop_event = (kind, sig, event)
                # If server does not specify a thread explicitly then assume that
                # current thread has not been changed.
                # XXX: There is no statement found in the protocol specification
                # about that aspect. Moreover, it's server implementation
                # dependent. So, a user must manage threads carefully with respect
                # to the implementation.
                if b"thread" in event:
                    self.thread = event[b"thread"]
                self.handle_br()
                if self.exit:
                    return
                # Some threads can be created during the breakpoint handling.
                # `cont_all` resumes them..
                kind, sig, data = stop_reply(self.cont_all())
            else:
                break

        if kind == b'W': # The process exited, getting values is impossible
            return

        if (kind, sig) != (b'T', 0x0b): print('strange signal %s' % sig)
        if hasattr(self, 'checkfault'):
            self.checkfault()
        else:
            src_line = self.get_src_line(int(self.regs[self.pc_reg],16 - 1))
            if src_line:
                print("0 %s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line']))
            else:
                print("%s %s" % (self.pc_reg, self.regs[self.pc_reg]))
            if isinstance(self, CortexM3):
                src_line = self.get_src_line(int(self.regs['lr'],16) -3)
                if src_line:
                    print("1 %s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line']))
                else:
                    print('lr %s' % s(self.regs['lr']))
            self.dump_regs()

        self.read_ack(20)

        self.port.close(self)
        sys.exit(0)

    def handle_br(self):
        """ dumps register on breakpoint/signal, continues if unknown,
            otherwise it calls the appropriate callback.
        """
        if self.verbose:
            print("")
            self.dump_regs()
        else:
            self.refresh_regs()
        if not self.regs[self.pc_reg] in self.br:
            print("unknown break point passed")
            self.dump_regs()
            return
        if self.verbose:
            br = self.br[self.regs[self.pc_reg]]
            print('breakpoint hit: %s' % (br['sym'] or "0x%s" % s(br['addr'])))
        self.br[self.regs[self.pc_reg]]['cb']()

    def set_br(self, sym, cb, quiet=False):
        """ sets a breakpoint at symbol sym, and install callback cb
            for it
        """
        addr = self.elf.symbols.get(sym)
        if not addr:
            print("unknown symbol: %s, ignoring request to set br" % sym)
            return
        if isinstance(self, CortexM3):
            addr &= ~1
        addr = self.reg_fmt % addr
        self.set_br_a(addr, cb, quiet=quiet, sym=sym)

    def set_br_a(self, addr, cb, quiet=False, sym=None):
        """ Sets a breakpoint at address, and install callback cb for it.

            `addr` is a hexadecimal string as defined by RSP protocol.
            Also, because of this RSP implementation `addr` format should be
            the same as defined by `reg_fmt`.

            Tips:
            - Use `reg_fmt` attribute to get `addr` string from an integer.
            - Normally, an unparsed register value has the same format and can
              be used as is.
        """
        if addr in self.br:
            print("warn: overwriting breakpoint at %s" % (sym or "0x" + addr))
            br = self.br[addr]
            br.update(sym = sym, cb = cb)
        else:
            self.br[addr]= br = {'sym': sym, 'addr': addr, 'cb': cb}
            if self.z_breaks:
                tmp = self.fetch(b'Z0,%s,2' % addr)
                if tmp == b"":
                    # Z/z packages are not supported, use code patching
                    self.z_breaks = False
                    br['old'] = unhex(self.fetch(b'm%s,2' % addr))
                    tmp = self.fetch(b'X%s,2:\xbe\xbe' % addr)
            else:
                br['old'] = unhex(self.fetch(b'm%s,2' % addr))
                tmp = self.fetch(b'X%s,2:\xbe\xbe' % addr)

            if self.verbose and not quiet:
                print("set break: @%s (0x%s) %s" % (sym or "[unknown]", s(addr), s(tmp)))

    def del_br(self, addr, quiet=False):
        """ deletes breakpoint at address addr """
        #self.fetch('z0,%s,2' % addr)
        if 'old' in self.br[addr]:
            tmp = self.fetch(b'X%s,2:%s' % (addr, self.br[addr]['old']))
            if self.verbose and not quiet:
                sym = self.br[addr]['sym'] or "[unknown]"
                print("clear breakpoint: @%s (0x%s) %s" % (sym, s(addr), s(tmp)))
        else:
            tmp = self.fetch(b'z0,%s,2' % addr)
            if tmp!= b'OK':
                print("failed to clear break: @%s (0x%s) %s" % ('FaultHandler', s(addr), s(tmp)))
            elif self.verbose and not quiet:
                print("clear break: @%s (0x%s) %s" % ('FaultHandler', s(addr), s(tmp)))

        del self.br[addr]

    def finish_cb(self):
        """ final breakpoint, if hit it deletes all breakpoints,
            continues running the cpu, and detaches from the debugging
            device
        """
        # clear all breaks
        for br in tuple(self.br.keys()):
            self.del_br(br)
        if self.verbose:
            print("continuing and detaching")
        # leave in running state
        self.send(b'c')
        self.exit = True

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
        back = self.br[self.regs[self.pc_reg]]
        addr = self.regs[self.pc_reg]
        self.del_br(addr, quiet=True)
        kind, sig, _ = stop_reply(self.step())
        if kind in (b'T', b'S') and sig in (5, 0x0b):
            self.set_br_a(addr, back["cb"], quiet=True, sym=back["sym"])
        else:
            print('strange signal while stepi over br, abort')
            sys.exit(1)

    def dump_cb(self):
        """ rsp_dump callback, hit if rsp_dump is called. Outputs to
            stdout the source line, and a hexdump of the memory
            pointed by $r0 with a size of $r1 bytes. Then it resumes
            running.
        """
        src_line = self.get_src_line(int(self.regs['lr'],16) - 3)
        if src_line:
            print("%s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line']))

        res_size = int(self.regs['r1'],16)
        if res_size <= 2048: # for sanity
            ptr = int(self.regs['r0'],16)
            res = unhex(self.fetch(b'm%x,%x' % (ptr, res_size)))
            print(hexdump(res, ptr))

        self.step_over_br()

    def load(self, verify):
        """ loads binary belonging to elf to beginning of .text
            segment (alias self.elf.workarea), and if verify is set read
            it back and check if it matches with the uploaded binary.
        """
        if self.verbose: print('load %s' % self.elf.name)
        buf = self.elf.get_bin()
        self.store(buf)

        if verify:
            if self.verbose: print("verify test")
            if not self.dump(len(buf)) == buf:
                raise ValueError("uploaded binary failed to verify")
            if self.verbose: print('OK')

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
        self.set_br('rsp_detach', self.finish_cb)
        self.set_br(dump, self.dump_cb)
        self.run(start)

    def test(self):
        # show current regs
        self.dump_regs()

        # test write
        self.fetchOK(b'X%08x,0' % self.elf.workarea)

        # reset workspace area
        self.store(b'\x00' * 2048)

        # verify workspace area empty
        if self.dump(2048) != b'\x00' * 2048:
            raise ValueError('cannot erase work area')

    def get_arg(self, n):
        "Returns hex encoded value of argument #n of current function call"
        try:
            # call_regs attribute is set by either user or predefined
            # targets (below)
            reg_name = self.call_regs[n - 1]
        except IndexError:
            # TODO: implement getting from stack
            raise NotImplementedError(
                "Getting of argument #%d is not implemented" % n)
        return self.regs[reg_name]

from .cortexhwregs import *
class CortexM3(RSP):
    def __init__(self, *args,**kwargs):

        self.arch = {'regs': ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
                              "r9", "r10", "r11", "r12", "sp", "lr", "pc",
                              "xpsr", "msp", "psp", "special"],
                     'endian': True,
                     'bitsize': 32}
        self.pc_reg = "pc"
        super(CortexM3,self).__init__(*args, **kwargs)

    def get_thread_info(self):
        return

    def getreg(self,size,ptr):
        tmp = self.fetch(b'm%x,%x' % (ptr, size))
        return unhex(switch_endian(tmp))

    def printreg(self, reg):
        return [n if type(v)==bool and v==True else (n,v if n!='ADDR' else hex(v<<5)) for n,v in reg.items() if v]

    def dump_mpu(self):
        print('mpu_cr %s' % self.printreg(mpu_cr.parse(self.getreg(4, MPU_CR))))
        for region in range(8):
            self.store(struct.pack("<I", region), MPU_RNR)
            print("%s %s %s" % (region,
                                self.printreg(mpu_rbar.parse(self.getreg(4, MPU_RBAR))),
                                self.printreg(mpu_rasr.parse(self.getreg(4, MPU_RASR)))
                                ))

    def checkfault(self):
        # impl check, only dumps now.
        #kind, sig, data = stop_reply(self.step())
        #print('sig %s' % sig)
        self.dump_mpu()
        print('hfsr= %s' % self.printreg(scb_hfsr.parse(self.getreg(4, SCB_HFSR))))
        print('icsr= %s' % self.printreg(scb_icsr.parse(self.getreg(4, SCB_ICSR))))
        print('shcsr= %s' % self.printreg(scb_shcsr.parse(self.getreg(4, SCB_SHCSR))))
        print('cfsr= %s' % self.printreg(scb_cfsr.parse(self.getreg(4, SCB_CFSR))))
        print('MMFAR= %s' % hex(struct.unpack(">I", self.getreg(4, SCB_MMFAR))[0]))
        print('BFAR= %s' % hex(struct.unpack(">I", self.getreg(4, SCB_BFAR))[0]))
        print("")
        src_line = self.get_src_line(struct.unpack(">I", self.getreg(4, int(self.regs['sp'],16) + 24))[0])
        if src_line:
            print("%s:%s %s" % (src_line['file'], src_line['lineno'], src_line['line']))
        else:
            print('sp %08x' % struct.unpack(">I", self.getreg(4, int(self.regs['sp'],16) + 24))[0])

        self.port.close(self)
        sys.exit(0)

    def connect(self):
        """ attaches to blackmagic jtag debugger in swd mode """
        # ignore redundant stuff
        tmp = self.readpkt(timeout=1)
        while(tmp):
            tmp = self.readpkt(timeout=1)
        # enable extended mode
        self.extended = self.fetch(b'!') == b"OK"

        # setup registers TODO
        # registers should be parsed from the output of, see target.xml
        #print(self.fetch('qXfer:features:read:target.xml:0,3fb'))
        #print(self.fetch('Xfer:features:read:target.xml:3cf,3fb'))
        #print(self.fetch('qXfer:memory-map:read::0,3fb'))
        #print(self.fetch('qXfer:memory-map:read::364,3fb'))

        self.port.setup(self)

        addr=struct.unpack(">I", self.getreg(4, 0x0000000c))[0] - 1
        addr = self.reg_fmt % addr
        self.br[addr]={'sym': "FaultHandler", 'addr': addr,
                             'cb': self.checkfault}
        tmp = self.fetch(b'Z1,%s,2' % addr)
        if tmp== b'OK':
            if self.verbose: print("set break: @%s (0x%s) %s" % ('FaultHandler', s(addr), s(tmp)))
            return

        # vector_catch enable hard int bus stat chk nocp mm reset
        self.send(b'qRcmd,766563746f725f636174636820656e61626c65206861726420696e742062757320737461742063686b206e6f6370206d6d207265736574')
        pkt=self.readpkt()
        while pkt!=b'OK':
            if pkt[:1]!=b'O':
                raise ValueError('not O: %s' % s(pkt))
            if self.verbose:
                print(unhex(pkt[1:-1]))
            pkt=self.readpkt()

    call_regs = ("r0", "r1", "r2", "r3")

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
                     'endian': True,
                     'bitsize': 64}
        self.pc_reg = "rip"
        super(AMD64,self).__init__(*args, **kwargs)

    # System V AMD64 ABI calling convention is assumed
    call_regs = ("rdi", "rsi", "rdx", "rcx", "r8", "r9") + tuple("xmm%d" for d in range(8))

class i386(RSP):
    # TODO gdb sends qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+
    def __init__(self, *args,**kwargs):
        self.arch = {'regs': ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                             "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
                             "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
                             "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
                             "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                             "mxcsr"],
                    'endian': True,
                    'bitsize': 32}
        self.pc_reg = "eip"
        super(i386,self).__init__(*args, **kwargs)

    # fastcall calling convention is assumed
    call_regs = ("ecx", "edx")

archmap={'amd64': AMD64, "x86_64": AMD64, "i386": i386, "cortexm3": CortexM3}

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
        print("%s [<%s>] <serial interface> [<elf file>]" % (sys.argv[0],
                                                             '|'.join(archmap.keys())))
        sys.exit(1)

    elffile=sys.argv[2] if len(sys.argv)>2 else None

    rsp = arch(sys.argv[1], elffile, verbose=False)

    if elffile:
        try:
            rsp.call()
        except KeyboardInterrupt:
            import traceback
            traceback.print_exc()

            rsp.read_ack(20)

            rsp.port.close(rsp)
            sys.exit(1)
    else:
        print(hexdump(rsp.dump(2048, 0),0))
        rsp.dump_regs()
        print(rsp.get_thread_info())
        rsp.send(b'c')
    rsp.port.close(rsp)

if __name__ == "__main__":
    main()
