#sqlparse.py
#
#This program parses an SQLite3 database for deleted entires and
#places the output into either and TSV file, or text file
#
#The SQLite file format, offsets etc is described at
#sqlite.org/fileformat.html
#
#
# Copyright (C) 2015 Mari DeGrazia (arizona4n6@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Version History:
# v1.1 2013-11-05
#
# v1.2 2015-06-20
#support added in to print out non b-tree pages
#
# v.1.3 2015-06-21
#minor changes / comments etc.
# 
#		
#Find a bug???? Please let me know and I'll try to fix it (if you ask nicely....)
#

import struct
import sys
import os

#function to remove the non-printable characters, tabs and white spaces

class sqlite_rec(object):

    def __init__(self,file_path):
        self.file_path = file_path
        try:
            self.file_in=open(self.file_path,"rb")
           
        except:
            return None
        
    def _remove_ascii_non_printable(self, chunk):
        chunk = ' '.join(chunk .split())
        return ''.join([ch for ch in chunk if ord(ch) > 31 and ord(ch) < 126 or ord(ch) ==9])

    #get the file size, we'll need this later
    #filesize = len(f.read())
    # Cheeky suggestion ... so it doesnt read the whole file unecessarily


    def extract_deleted(self):

        stats = os.stat(self.file_path)
        filesize = stats.st_size

        #be kind, rewind (to the beginning of the file, that is)
        self.file_in.seek(0)

        #verify the file is an sqlite db; read the first 16 bytes for the header
        header = self.file_in.read(16)
        
        if "SQLite" not in header:
            return "File does not appear to be an SQLite File"
            


        #OK, lets get started. The SQLite database is made up of multiple Pages. We need to get the size of each page.
        #The pagesize this is stored at offset 16 at is 2 bytes long

        pagesize = struct.unpack('>H', self.file_in.read(2))[0]

        #According to SQLite.org/fileformat.html,  all the data is contained in the table-b-trees leaves.
        #Let's go to each Page, read the B-Tree Header, and see if it is a table b-tree, which is designated by the flag 13

        #set the offset to 0, so we can also process any strings in the first page
        offset = 0

        #while the offset is less then the filesize, keep processing the pages

        ret_list = []
        while offset < filesize: 
            
            #move to the beginning of the page and read the b-tree flag, if it's 13, its a leaf table b tree and we want to process it
            self.file_in.seek(offset)
            flag = struct.unpack('>b',self.file_in.read(1))[0]

            if flag == 13:

                #this is a table_b_tree - get the header information which is contained in the first 8 bytes

                freeblock_offset = struct.unpack('>h',self.file_in.read(2))[0] 
                num_cells = struct.unpack('>h',self.file_in.read(2))[0]
                cell_offset = struct.unpack('>h',self.file_in.read(2))[0]
                num_free_bytes = struct.unpack('>b',self.file_in.read(1))[0]


                #unallocated is the space after the header information and before the first cell starts 

                #start after the header (8 bytes) and after the cell pointer array. The cell pointer array will be the number of cells x 2 bytes per cell
                start = 8 + (num_cells * 2)

                # the length of the unallocated space will be the difference between the start and the cell offset
                length = cell_offset-start

                #move to start of unallocated, then read the data (if any) in unallocated - remember, we already read in the first 8 bytes, so now we just need to move past the cell pointer array
                self.file_in.read(num_cells*2)
                unallocated = self.file_in.read(length)

           
                #lets clean this up so its mainly the strings - remove white spaces and tabs too

                unallocated  = self._remove_ascii_non_printable(unallocated )
                if unallocated != "":
                    ret_list.append( [ "Unallocated",  str(offset+start), str(length), str(unallocated) ] )   

                #if there are freeblocks, lets pull the data

                while freeblock_offset != 0:
                    #move to the freeblock offset
                    self.file_in.seek(offset+freeblock_offset)
                    #get next freeblock chain
                    next_fb_offset = struct.unpack('>h',self.file_in.read(2))[0]
                    #get the size of this freeblock
                    free_block_size = struct.unpack('>hh',self.file_in.read(4))[0]
                    #move to the offset so we can read the free block data
                    self.file_in.seek(offset+freeblock_offset)
                    #read in this freeblock
                    free_block = self.file_in.read(free_block_size)
                    #lets clean this up so its mainly the strings - remove white spaces and tabs too
                    free_block  = self._remove_ascii_non_printable(free_block)
                    if unallocated != "":
                        ret_list.append( ["Free Block",  str(offset+freeblock_offset), str(free_block_size), str(free_block) ])
                    freeblock_offset = next_fb_offset


                #increase the offset by one pagesize and loop
            offset = offset + pagesize
        return ret_list

