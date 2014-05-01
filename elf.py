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

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def get_symbols(fname):
    with open(fname,'r') as stream:
        elffile = ELFFile(stream)
        section = elffile.get_section_by_name(b'.symtab')
        if not section:
            raise ValueError('No symbol table found. Perhaps this ELF has been stripped?')

        res = {}
        if isinstance(section, SymbolTableSection):
            for i in xrange(section.num_symbols()):
                res[bytes2str(section.get_symbol(i).name)]=(section.get_symbol(i).entry.st_value)
        return res
