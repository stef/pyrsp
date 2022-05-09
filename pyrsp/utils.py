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

from socket import socket, AF_INET, SOCK_STREAM
from time import time
from json import JSONDecoder, JSONEncoder
from six import PY3
from psutil import net_connections

_json_decoder, _json_encoder = JSONDecoder(), JSONEncoder()

if PY3:
    def qmp_encode(_dict):
        return _json_encoder.encode(_dict).encode("utf-8")
    def qmp_decode(_bytes):
        return _json_decoder.raw_decode(_bytes.decode("utf-8"))
else:
    qmp_encode = _json_encoder.encode
    qmp_decode = _json_decoder.raw_decode

class QMP(object):
    """ QEMU Monitor Protocol client over TCP.
See: https://wiki.qemu.org/Documentation/QMP
    """

    def __init__(self, port, host = "localhost"):
        self._sock = socket(AF_INET, SOCK_STREAM)
        self._sock.connect((host, port))

        # Wait for QEMU QMP prompt
        self.qmp_info = qmp_decode(self.next_json_object)[0]
        # Mandatory request for capabilities
        self.qmp_caps = self("qmp_capabilities")["return"]

    @property
    def next_json_object(self):
        sock = self._sock
        c = None
        # wait for beginning of JSON object
        while c != b'{':
            c = sock.recv(1)
        res = c
        in_str = None
        escaping = False
        nesting = 1
        while nesting > 0:
            c = sock.recv(1)
            if in_str is None:
                if c == b'{':
                    nesting += 1
                elif c == b'}':
                    nesting -= 1
                elif c == b'"' or c == b"'":
                    in_str = c
            else:
                if escaping:
                    escaping = False
                else:
                    if c == b'\\':
                        escaping = True
                    elif c == in_str:
                        in_str = None

            res += c
        return res

    def __call__(self, command, _id = None, control = None, args = {}, **kw):
        request = dict(execute = command)
        if control is not None:
            request["control"] = control
        if _id is not None:
            request["id"] = _id
        # Never update `args` with `kw` because this affect other calls!
        kw.update(args)
        if kw:
            request["arguments"] = kw

        self._sock.send(qmp_encode(request) + b"\r\n")

        response = qmp_decode(self.next_json_object)[0]

        if "error" in response:
            raise RuntimeError("QMP Error: " + str(response))
        return response


if PY3:
    charcodes = lambda data: iter(data)
    characters = lambda data: map(chr, data)
    # charmap is a fast encoder which supports all byte values [0, 255].
    s = lambda data: data.decode("charmap")
else:
    charcodes = lambda data: map(ord, data)
    characters = lambda data: iter(data)
    s = lambda data: data

s.__doc__ = """Given bytes data, returns it as `str` in Python version
independent manier."""

checksum = lambda data: sum(charcodes(data)) & 0xff

# precompute escapes for `pack`
UNESCAPE = [b"%c" % code for code in range(256)]
for x in [b'}', b'*', b'#', b'$']:
    UNESCAPE[ord(x)] = b"}%c" % (ord(x) ^ 0x20)

def pack(data):
    """ formats data into a RSP packet """
    res = b"$"
    _sum = 0
    for code in charcodes(data):
        res += UNESCAPE[code]
        for check_byte in UNESCAPE[code]:
            _sum += check_byte              #the escape character and the XORed byte is part of the checksum
    res += b"#%02x" % (_sum & 0xff)
    return res

def unpack(pkt):
    """ unpacks an RSP packet, returns the data"""
    if pkt[:1] != b'$' or pkt[-3:-2] != b'#':
        raise ValueError('bad packet')
    if checksum(pkt[1:-3]) != int(pkt[-2:], 16):
        raise ValueError('bad checksum')
    pkt = pkt[1:-3]
    return pkt


def unhex(data):
    """ takes a hex encoded string and returns the binary representation """
    return b''.join(b"%c" % int(x, 16) for x in split_by_n(data, 2))

def switch_endian(data):
    """ byte-wise reverses a hex encoded string """
    return b''.join(reversed(list(split_by_n(data, 2))))

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units.
       src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character"""
    while seq:
        yield seq[:n]
        seq = seq[n:]

def hexdump(data, ptr=0):
    """ returns data formatted as a hexdump """
    return "\t%s" % '\n\t'.join(
        "%08x | %s %s" % (
            (i << 5) + ptr,
            ' '.join(
                ''.join(map(
                    "%02x".__mod__, charcodes(word)
                )) for word in split_by_n(line, 8)
            ),
            ''.join(c if c.isalnum() else '.' for c in characters(line))
        ) for i, line in enumerate(split_by_n(data, 32))
    )

def find_free_port(start = 4321):
    "Search free TCP port for listening."

    for port in range(start, 1 << 16):
        test_socket = socket(AF_INET, SOCK_STREAM)
        try:
            test_socket.bind(("", port))
        except:
            pass
        else:
            return port
        finally:
            test_socket.close()
    # return None

def wait_for_tcp_port(port, timeout = 5.0):
    t0 = time()
    while time() - t0 < timeout:
        conns = net_connections(kind = "tcp4")
        for conn in conns:
            # Note that laddr became a named tuple only since 5.3.0
            if conn.laddr[1] == port:
                # If a process using that port just terminated, the connection
                # can still be in the `conns` list. But a connection attempt
                # will be refused. We wait for an alive process listening
                # the port.
                if conn.pid is None:
                    break
                return True
    return False

def rsp_decode(data):
    """ Decodes run-length encoded data.
        See: https://sourceware.org/gdb/onlinedocs/gdb/Overview.html
    """
    return b"".join(rsp_decode_parts(data))

def rsp_decode_parts(data):
    """ An internal variant of run-length decoder.
        It yields parts of decoded data.
    """
    parts = data.split(b'*')
    i = iter(parts)
    prev = next(i)
    yield prev
    for cur in i:
        if cur:
            n = ord(cur[:1]) - 29
            yield prev[-1:] * n
            yield cur[1:]
        else:
            # empty part means paired stars, one by one
            yield prev[-1:] * 13 # ord("*") - 29
            try:
                cur = next(i)
            except StopIteration:
                break
            yield cur
        prev = cur

def stop_reply(packet):
    """ Parses Stop Reply Packet
        See: https://sourceware.org/gdb/onlinedocs/gdb/Stop-Reply-Packets.html

        :returns: tuple (kind, signal, data), signal and data can be None
    """
    kind = packet[:1]
    if kind == b'T':
        signal, data = int(packet[1:3], 16), packet[3:]
    elif kind == b'S':
        signal, data = int(packet[1:3], 16), None
    elif kind == b'N':
        signal, data = None, None
    elif kind in (b'O', b'F'):
        signal, data = None, packet[1:]
    elif kind in (b'W', b'X', b'w'):
        if len(packet) > 3:
            # multiprocess
            kind_signal, data = packet.split(b";", 1)
            signal = int(kind_signal[1:], 16)
        else:
            signal, data = int(packet[1:3], 16), None

    return kind, signal, data

def stop_event(data):
    """ Parses data of 'T' Stop Reply Packet

        :returns: dict
    """
    event = {}

    while data:
        pair, data = data.split(b';', 1)
        n, r = pair.split(b':', 1)
        event[n] = r

    return event
