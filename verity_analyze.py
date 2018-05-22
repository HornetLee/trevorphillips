from binascii import hexlify
from binascii import unhexlify

import hashlib
import os,sys

#corrupt analyze result 

report_depth = 0
class Analyzer:
	
	def __init__(self, log_info, image_parsers):
		self.log_info = log_info
		self.parsers = image_parsers

		self.corrupt_report = {}
		self.report_buffer = []
	def start(self):
		
		r = self.corrupt_report
		
		log_info = self.log_info
		
		print (log_info.fips_status)
		if log_info.fips_status == 'failure':
			r.update({'PRE-DMV ERR' : {} })
			
			err_dict = r['PRE-DMV ERR']
			err_dict['RESULT'] = 'dm-verity setup had failed.'
			err_dict['DETAIL'] = 'FIPS POST was unsuccessful.'
			err_dict['RESOLUTION'] = 'Please contact : jungha.paik'
			return

		if not log_info.verity_corruption:
			r.update({'PRE-DMV ERR' : {} })
			
			err_dict = r['PRE-DMV ERR']
			err_dict['RESULT'] = 'No dm-verity corruption is found in log'
			err_dict['DETAIL'] = ''
			err_dict['RESOLUTION'] ='Please check if the log is from problematic situation'
			return 
		

		corrupt_n = 0
		corrupt_list = log_info.verity_corruption
		
		for corrupt in corrupt_list:
			corrupt_n = corrupt_n +1
			r.update({'CORRUPT#'+str(corrupt_n) : { } })
			corrupt_dict = r['CORRUPT#'+str(corrupt_n)]	
			
			parser = self.get_image_parser(corrupt)
			block_n = corrupt.block_n
			verity_block = parser.read_block(block_n)
			#print verity_block
			if not verity_block:
				corrupt_dict['RESULT'] = 'Error - No matching image found with this corrupt !'
				corrupt_dict['DETAIL'] = ''
				corrupt_dict['RESOLUTION'] = 'Please check if downloaded image\'s QBID matches that in kernel log.' 
				continue

			if not self.is_valid(corrupt):
				corrupt_dict['RESULT'] = 'Error - Dumped bytes for block#' + str(corrupt.block_n) + ' has incomplete or corrupted hexadecimal character([0-9a-f]) !'
				corrupt_dict['DETAIL'] = ''
				corrupt_dict['RESOLUTION'] = 'please use complete kernel log'
				continue

			m  = self.check_VA_status(corrupt)
			if m:
				corrupt_dict['RESULT'] = 'Invalid kerenl space address used for dm-verity buffer.'
				corrupt_dict['DETAIL'] = m 
				corrupt_dict['RESOLUTION'] = 'Need to check DRAM first. Please contact : j.gap.lee'
				continue
			
			m = self.check_hash_calc_status(corrupt)
			if m:
				corrupt_dict['RESULT'] = 'Crypto hash calculation error found.'
				corrupt_dict['DETAIL'] = m
				corrupt_dict['RESOLUTION'] = 'AP malfunction in ARM CE is suspected. Please contact : '
				continue

			m = self.check_block_read_status(corrupt,verity_block)
			if m:
					corrupt_dict['RESULT'] = 'Wrong data had been loaded to memory when calculating hash digest'
					corrupt_dict['DETAIL'] = m['detail']
					corrupt_dict['RESOLUTION'] =m['resolution']
					continue
			
			corrupt_dict['RESULT'] = "digest , data , hash calulation all match.."
			corrupt_dict['DETAIL'] = "Nowhere to complain"
			corrupt_dict['RESOLUTION'] = 'Please contact hk1982.lee'
			continue
		
	def check_VA_status(self,corrupt):
		
		va_dict = {'real digest' : corrupt.r_digest_va , 'want digest' : corrupt.w_digest_va , 'block data' : corrupt.block_data_va}
		
		for key in va_dict:
			if not va_dict[key].startswith('0xffffff'):
				return 'kernel tried to access ' + va_dict[key] + ', which is not part of kernel address space.'

		return None

	def check_block_read_status(self, corrupt, verity_block):

		diff_bytes  = 0
		
		size = 0
		ret = {}
		
		parser = self.get_image_parser(corrupt)
		image_info = parser.image_info
		
		w_digest = unhexlify(corrupt.w_digest)
		if corrupt.block_type == 'data':
			size = 32
			for b in range(size):
				if w_digest[b] != verity_block.L0_hash[b]:
					diff_bytes = diff_bytes + 1

			if diff_bytes > (size / 2):
				if w_digest == b'\xff'*size:
					ret['detail'] = 'All 0xff byte was read which suggests UFS read error'
					ret['resolution'] ='Need to check UFS driver layer or below first. Contact : jangsub.yi'
					return ret

				#search hash digest in entire partition, if exists
				for key in self.parsers:
					search_result = self.parsers[key].search(w_digest)
					if search_result:
						
						ret['detail'] = 'Wrong hash digest is loaded' + '\n' \
						                + '- expected digest : ' + 'block#' + str(corrupt.block_n) + '\'s digest' + ' ,' + image_info.verity_meta.part_name + '\n' \
										+ '- digest found at : ' + 'block#' + str(search_result)   + '\'s digest' +  ',' + self.parsers[key].image_info.verity_meta.part_name + '\n' \
										
						ret['resolution'] = 'Need to check '
						return ret
				
				if not search_result:
					ret['detail'] = 'Kernel(dm-verity) tried to verify data that is not found in any partitions' + '\n' \
					                '@block#' + str(corrupt.block_n) + ' ,' + image_info.verity_meta.part_name
					ret['resolution'] = 'If this issue happened during FOTA, DUT may have gone through incomplete updates. Contact: ' + '\n' \
					                    + 'Otherwise, contact hk1982.lee'
					return ret
			elif diff_bytes !=0 and diff_bytes <= (size / 2):
				ret['detail']= diff_bytes + ' byte(s) difference found' + '\n' \
							   + '@block#'+ str(corrupt.block_n) + ' ,' +parser.image_info.part_name + ' ,' + corrupt.w_digest_va + '\n' \
							   + '- expected digest :' + hexlify(verity_block.L0_hash) + '\n' \
							   + '- read digest     :' + hexlify(w_digest)
				ret['resolution']='Need to check DRAM first. Please contact : j.gap.lee'
				return ret

			
			#4k block check
			size = 4096
			first_diff = -1
			block_data = unhexlify(corrupt.block_data)

			for b in range(size):
				if block_data[b] != verity_block.data[b]:
					if first_diff < 0:
						first_diff = b

					diff_bytes = diff_bytes + 1
		
			if diff_bytes > (size / 2):
				
				if block_data == b'\xff'*size:
					ret['detail'] = 'All 0xff byte was read which suggests UFS read error'
					ret['resolution'] ='Need to check UFS driver layer or below first. Contact :jangsub.yi'
					return ret
				#search hash digest in entire partition, if exists
				ret['detail'] = 'Wrong data block is loaded' + '\n' \
						        + '- expected data : ' + '@block# ' + str(corrupt.block_n) + ' ,' + image_info.verity_meta.part_name + '\n'
				for key in self.parsers:
					search_result = self.parsers[key].search(block_data)
					if search_result:
						ret['detail'] +='- data found at : ' + '@block# ' + str(search_result)   + ' ,' + self.parsers[key].image_info.verity_meta.part_name + '\n'
				
				if search_result:
					ret['resolution'] = 'Need to check UFS driver layer or below. Please contact: jangsub.yi'
					
				else:
					ret['detail'] = 'Kernel(dm-verity) tried to verify data that is not found in any partitions'
					ret['resolution'] = 'If this issue happened during FOTA, DUT may have gone through incomplete updates. Contact: ' + '\n' \
						                + 'Otherwise, contact hk1982.lee'
				return ret
			elif diff_bytes !=0 and diff_bytes <= (size /2):
				start = (first_diff >> 4 ) << 4 
				offset = first_diff % 16
				
				v_line = hexlify(verity_block.data[start : start+16]).decode()
				c_line = hexlify(block_data[start : start+16]).decode()
				
				ret['detail']= str(diff_bytes) + ' byte(s) difference found' \
							   + ' @block#'+ str(corrupt.block_n) + ' ,' +image_info.verity_meta.part_name + ' ,' + corrupt.block_data_va + '\n' \
							   + '- expected data :' + hex(start) + ' : ' + v_line[:offset*2] + '<' + v_line[offset*2] + '>' + v_line[offset*2 +1:] + '\n' \
							   + '- read data     :' + hex(start) + ' : ' + c_line[:offset*2] + '<' + c_line[offset*2] + '>' + c_line[offset*2 +1:]
				ret['resolution'] = 'Need to check DRAM first. Please contact : j.gap.lee'
				return ret

		elif corrupt.block_type == 'meta':
			pass

	def get_image_parser(self,corrupt):
		if corrupt.salt_digest:
			for key in self.parsers:
				image_info = self.parsers[key].image_info.verity_meta
				if(image_info.salt == corrupt.salt_digest):
					return self.parsers[key]
		
		return self.parsers['system']



	def get_report(self):
		return self.corrupt_report
	
	def show_report(self):

		for key in sorted(self.corrupt_report):
			
			if key.startswith('CORRUPT'):
				print ('\ndm-verity corrupt found in log')
			else:
				print ('\npre-dmverity error found in log')
			print ('<'+ key + '>')
			print ('a.result')
			print (': '+ self.corrupt_report[key]['RESULT'])
			print ('b.detail')
			print (': '+self.corrupt_report[key]['DETAIL'])
			print ('c.resolution')
			print (': '+self.corrupt_report[key]['RESOLUTION'])
	
	def save_report_to_file(self,report_dir):
		with open(report_dir+'/report','w') as f:
			for key in sorted(self.corrupt_report):
			
				if key.startswith('CORRUPT'):
					f.write('\n\ndm-verity corrupt found in log')
				else:
					f.write('\npre-dmverity error found in log')
				f.write ('\n<'+ key + '>')
				f.write('\na.result')
				f.write('\n: '+ self.corrupt_report[key]['RESULT'])
				f.write ('\nb.detail')
				f.write ('\n: '+self.corrupt_report[key]['DETAIL'])
				f.write ('\nc.resolution')
				f.write ('\n: '+self.corrupt_report[key]['RESOLUTION'])		
	
	def save_block_to_file(self, report_dir):
		report_path = report_dir

		corrupts     = self.log_info.verity_corruption
		corrupt_n = 0
		for c in corrupts:
			corrupt_n = corrupt_n + 1
			block_n       = c.block_n
			parser = self.get_image_parser(c)
			verity_block = parser.read_block(block_n)
			part_name    = parser.image_info.verity_meta.part_name
			
			file_corrupt = os.path.join(report_path, 'log_' + str(block_n) + '_' + str(corrupt_n) +'_' + str(part_name))   
			file_rbs     = os.path.join(report_path, 'rbs_' + str(block_n) + '_' + str(part_name))
			with open(file_corrupt,'wb') as f:
				f.write(unhexlify(c.block_data))
			with open(file_rbs,'wb') as f:
				f.write(verity_block.data)

	def check_hash_calc_status(self,corrupt):
		parser = self.get_image_parser(corrupt)
		verity_meta = parser.image_info.verity_meta

		ret = {}

		if verity_meta.hash_algo == 'sha256':
			m = hashlib.sha256()
		elif verity_meta.hash_algo == 'sha1':
			m = hashlib.sha1()
		elif verity_meta.hash_algo == 'md5':
			m = hashlib.md5()
		else:
			m = None
		
		salt_byte = unhexlify(corrupt.salt_digest)
		block_data = unhexlify(corrupt.block_data)
		if verity_meta.verity_version == '1':
			m.update(salt_byte)
		
		m.update(block_data)
		
		if verity_meta.verity_version == '0':
			m.update(salt_byte)
		
		good_digest = m.digest()
		good_digest = hexlify(good_digest).decode('utf-8')
		if good_digest == corrupt.r_digest:
			return None
		else:
			info = 'Block #' + str(corrupt.block_n) + '\'s 4K bytes read data ' + corrupt.block_data[:4] + ' .... ' + corrupt.block_data[-4:] \
			                 + ' did not produce correct ' + verity_meta.hash_algo + ' digest.\n' \
							 + '- expected digest   : ' + good_digest + '\n' \
							 + '- calculated digest : ' + corrupt.r_digest
			return info
	
	def is_valid(self,corrupt):
		if corrupt.write_state == 'done':
			return True
		else:
			return False
