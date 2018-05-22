#! /usr/bin/python

class ImageInfo:
	def __init__(self):
		self.blocks={}
		self.verity_meta = None

class VerityBlock:
	
	def __init__(self):
		self.block_n = 0
		self.data=''
		self.L0_hash=''
		self.L0_data=''
		self.L1_hash=''
		self.L1_data=''
		self.L2_hash=''
		self.L2_data=''

class LogInfo:
	
	def __init__(self):
		self.qbid=""
		self.model=""
		self.verifiedbootstate=""
		self.security_mode=""
		self.fips_status=""
		self.verity_partition={}
		self.verity_corruption=[]

class Partition:
	part_name=''
	verity_version=""
	data_dev_name =""
	hash_dev_name =""
	data_block_size = 0
	hash_block_size = 0
	meta_start_offset = 0
	hash_start_offset = 0
	hash_algo =""
	root_hash=""
	salt=""
	
	def __init__(self, part_name):
		self.part_name = part_name
		self.hash_level_offset = {}
class Corruption:
	
	def __init__(self, core, block_n, block_type):

		self.core = core
		self.block_n = block_n
		self.block_type = block_type
		
		self.salt_digest = ''

		self.r_digest =''
		self.w_digest =''
		self.block_data  =''
		
		self.r_digest_va =''
		self.w_digest_va =''
		self.block_data_va =''

		self.r_digest_offset = 0x00
		self.w_digest_offset = 0x00
		self.block_data_offset = 0x00		

		self.write_state = 'r_digest'

		self.c_state = 'consistent'
		self.l_state = 'incomplete'
