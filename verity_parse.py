import os,sys,math,re
from ds       import *
from re_verity import *

import binascii
import struct
class ImageParser:

	def __init__(self, image_file):
		self.image_file = image_file
	
		self.image_info = ImageInfo()

	
	def read_verity_meta(self):
		with open(self.image_file, 'rb') as f:
			f.seek(0,2)
			size = f.tell()
			verity_size = int((size) / 32)
			verity_size = max(verity_size, 32 * 1024 * 1024)
			
			offset = size - verity_size
			f.seek(offset , 0)
		
			while(offset < size):
				s = f.read(4096)
				m = re.search(b'\x01\xb0\x01\xb0\x00\x00\x00\x00', s)
				if m:
					break
				else:
					offset = offset + 4096

			if not m:
				print ('cannot find verity table')
				return
			offset = offset + m.end() + 252
			f.seek(offset, 0)
			table_size = f.read(4)
			table_size = struct.unpack('<L' , table_size)[0]
			s = f.read(300)
			s  = s.decode('utf-8','replace')
			m = re.search(RE_VERITY_TABLE_IMAGE, s)
			
			if m:
				n = re.search(RE_VERITY_PART_NAME, m.group(2))
				part_name = n.group(1)
				part_name = part_name.lower()

				part = Partition(part_name)
				part.verity_version    = m.group(1)
				part.data_dev_name     = m.group(2)
				part.hash_dev_name     = m.group(3)
				part.data_block_size   = int(m.group(4))
				part.hash_block_size   = int(m.group(5))
				part.meta_start_offset = int(m.group(6))
				part.hash_start_offset = int(m.group(7))
				
				part.hash_algo         = m.group(8)
				part.root_hash         = m.group(9).lower()
				part.salt              = m.group(10).lower()
				
				hash_position = part.hash_start_offset

				for i in range(2,-1,-1):
					part.hash_level_offset[i] = hash_position
					s = (part.meta_start_offset + (1 << ((i+1) * 7)) - 1) >> ((i+1)*7)

					hash_position = hash_position + s

				self.image_info.verity_meta = part
	
	def read_block(self, block_n):
		with open(self.image_file, 'rb') as f:
				
				verity_meta = self.image_info.verity_meta
				
				data_offset = (block_n) * 4096
				L0_hash_start = (verity_meta.hash_level_offset[0]  << 12) 
				L1_hash_start = (verity_meta.hash_level_offset[1]  << 12)
				L2_hash_start = (verity_meta.hash_level_offset[2]  << 12)

				L0_offset =  (block_n        ) << 5			
				L1_offset =  (L0_offset >> 12) << 5
				L2_offset =  (L1_offset >> 12) << 5 

				L0_hash_offset = L0_hash_start + L0_offset
				L1_hash_offset = L1_hash_start + L1_offset
				L2_hash_offset = L2_hash_start + L2_offset
				
				verity_block = VerityBlock()
				verity_block.part_name = verity_meta.part_name
				verity_block.block_n = block_n
				
				f.seek(data_offset,0)
				byte = f.read(int(4096))
				verity_block.data = byte

				f.seek(L0_hash_offset,0)
				byte = f.read(int(32))
				verity_block.L0_hash = byte

				f.seek(L1_hash_offset,0)
				byte = f.read(int(32))
				verity_block.L1_hash = byte

				f.seek(L2_hash_offset,0)
				byte = f.read(int(32))
				verity_block.L2_hash = byte
				
				return verity_block

#find byte_seq in image and block offset

	def search(self,byte_seq):
		ret = []
		with open(self.image_file , 'rb') as f:
			f.seek(0,os.SEEK_END)
			file_size = f.tell()
			search_len = len(byte_seq)
			#search has tree first if byte sequence is hash digest
			
			end = file_size
			if search_len == 32:
				start = (self.image_info.verity_meta.hash_level_offset[0])<<12
				print ('search start offset ' + str(start))
				f.seek(start , os.SEEK_SET)
				
				while True:
					read_byte = f.read(search_len)
					if not read_byte:
						break
					
					if read_byte == byte_seq:
						found_offset = f.tell() - 32
						ret.append((found_offset - start) >> 5)

			elif search_len == 4096:
				start = 0

				f.seek(0, os.SEEK_SET)
				
				fs_size = (self.image_info.verity_meta.meta_start_offset) << 12
				while True:
					read_byte = f.read(search_len)
					if not read_byte:
						break
					if read_byte == byte_seq:
						found_offset = f.tell() - 4096
						ret.append((found_offset) >> 12)
		if not ret:
			return None
		else:
			return ret

class LogParser:
	
	def __init__(self,file_name):
		self.pattern_table   = re.compile(RE_VERITY_TABLE)
		self.pattern_block_n = re.compile(RE_VERITY_CORRUPT_BLOCK_N)
		self.pattern_salt    = re.compile(RE_VERITY_CORRUPT_SALT)
		self.pattern_VA      = re.compile(RE_VERITY_CORRUPT_VA)
		self.pattern_dump    = re.compile(RE_VERITY_CORRUPT_DUMP)
		self.pattern_fips    = re.compile(RE_VERITY_FIPS_FAILURE)
		self.pattern_qbid    = re.compile(RE_QB_ID)
		self.pattern_qbid2   = re.compile(RE_QB_ID2)

		self.log_info    = LogInfo() 
		self.file_name   = file_name
	
	def parse(self):
		with open(self.file_name, 'r',errors='ignore') as f:
			for line in f:
				self.parse_line(line)

	def parse_line(self, line):
		m = self.pattern_dump.match(line)
		if m:
			core   = m.group(1)
			offset = int(m.group(2), 16)
			dump   = m.group(3)
			dump = dump.replace(' ','')
			dump = dump[:32]

			for corrupt in self.log_info.verity_corruption:
				if corrupt.write_state == 'done':
					continue

				if corrupt.core == core:
					
					if corrupt.write_state == 'r_digest':
						corrupt.r_digest = corrupt.r_digest +dump
						offset = offset + 0x10
						if offset >= 0x20:
							corrupt.write_state = 'w_digest'
					
					elif corrupt.write_state == 'w_digest':
						corrupt.w_digest = corrupt.w_digest +dump
						offset = offset + 0x10
						if offset >= 0x20:
							corrupt.write_state = 'block'

					else:
						corrupt.block_data = corrupt.block_data + dump
						offset = offset +0x10
						if offset >= 0x1000:
							corrupt.write_state = 'done'

			return
		
		m= self.pattern_block_n.match(line)
		if m: 
			core       = m.group(1)
			block_type = m.group(2)
			block_n    = int(m.group(3))
			
			corrupt = Corruption(core, block_n, block_type)
			self.log_info.verity_corruption.append(corrupt)
			return

		m = self.pattern_salt.match(line)
		if m:
			core = m.group(1)
			salt = m.group(2)
			for corrupt in self.log_info.verity_corruption:
				if corrupt.core == core:
					corrupt.salt_digest = salt

			return

		m = self.pattern_VA.match(line)
		if m:
			core = m.group(1)
			VA   = m.group(2)
			for corrupt in self.log_info.verity_corruption:
				if corrupt.core == core:
					if not corrupt.r_digest_va:	
						corrupt.r_digest_va = VA
					elif not corrupt.w_digest_va:
						corrupt.w_digest_va = VA
					else:
						corrupt.block_data_va = VA
			return

		m = self.pattern_table.match(line)
		if m:
			n = re.search(RE_VERITY_PART_NAME, m.group(2))
			part_name = n.group(1)
			part_name = part_name.lower()

			part = Partition(part_name)
			part.verity_version    = m.group(1)
			part.data_dev_name     = m.group(2)
			part.hash_dev_name     = m.group(3)
			part.data_block_size   = m.group(4)
			part.hash_block_size   = m.group(5)
			part.meta_start_offset = m.group(6)
			part.hash_start_offset = m.group(7)
			part.hash_algo         = m.group(8)
			part.root_hash         = m.group(9)
			part.salt              = m.group(10)
			
			self.log_info.verity_partition[part_name] = part
			return

		m = self.pattern_fips.match(line)
		if m:
			self.log_info.fips_status = 'failure'
			return

		m = self.pattern_qbid.match(line)
		if m:
			self.log_info.qbid = m.group(1)
			return
		
		m = self.pattern_qbid2.match(line)
		if m:
			self.log_info.qbid = m.group(1)
			return

def parse_klog(klog, log_parser):
	with open(klog, "r") as f:
		for line in f:
			#print line
			log_parser.parse(line)		
			#print 'data_dev'+ m.group(2)
	
	#display(log_parser)


def display3(image_info):
	for key in image_info.blocks:
		with open('block_'+str(key), 'wb') as f:
			f.write(image_info.blocks[key].data)

def display4(log_info):
	for key in log_info.verity_partition:
		print (key)


