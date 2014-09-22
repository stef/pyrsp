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

def hexdump(data, ptr=0):
    """ returns data formatted as a hexdump """
    return "\t%s" % '\n\t'.join(["%08x | %s %s" % ((i*32)+ptr,
                                                   ' '.join([''.join(["%02x" % ord(c) for c in word])
                                                             for word in split_by_n(line,8)]),
                                                   ''.join([c if c.isalnum() else '.' for c in line]))
                                 for i, line in enumerate(split_by_n(data,32))])

