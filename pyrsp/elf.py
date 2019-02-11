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

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from six.moves import range
from pyrsp.utils import s

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
            try: self.fd = open(fname,'r')
            except: return ''
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

class ELF:
    def __init__(self, name):
        """ reads out the entry point, the .text segment addres, the
            symbol table, and the debugging information from the elf
            header.
        """
        self.name = name
        self.fcache = FCache()

        with open(self.name,'rb') as stream:
            elffile = ELFFile(stream)

            # get entry point
            self.entry = elffile.header.e_entry

            # get text seg address
            section = elffile.get_section_by_name('.text')
            if not section:
                raise ValueError('No text segment found.')
            self.workarea = section.header['sh_addr']

            # init symbols
            section = elffile.get_section_by_name('.symtab')
            if not section:
                raise ValueError('No symbol table found. Perhaps this ELF has been stripped?')

            res = {}
            if isinstance(section, SymbolTableSection):
                for i in range(section.num_symbols()):
                    res[section.get_symbol(i).name]=(section.get_symbol(i).entry.st_value)
            self.symbols = res

            self.src_map = self.get_src_map(elffile)

    def get_src_map(self, elffile):
        """ builds a dictionary of the DWARF information, used to populate
            self.src_map

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
                    fname = s(lineprogram['file_entry'][state.file - 1].name)
                    line = self.fcache.get_src_lines(cu_filename, state.line)
                    src_map["%08x" % state.address] = {'file': fname, 'lineno': state.line, 'line': line}
                    try:
                        src_map["%s:%s" % (fname, state.line)].append({'addr': "%08x" % state.address, 'line': line})
                    except KeyError:
                        src_map["%s:%s" % (fname, state.line)]= [{'addr': "%08x" % state.address, 'line': line}]
        return src_map

    def get_bin(self):
        """ returns the .text and .rodata sections from elf file fname
        """
        with open(self.name,'r') as stream:
            elffile = ELFFile(stream)

            # get text seg address
            txt = elffile.get_section_by_name('.text')
            if not txt:
                raise ValueError('No text segment found.')
            return txt.data()
