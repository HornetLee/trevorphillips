#! /usr/local/bin/python3

import os,sys,math,re
import datetime,time
import argparse

from ds import *
from verity_parse import *
from verity_analyze import *
import subprocess 

from downloader import *

def decompress_qb_bin(qb_bin_dir):
	
	verity_image = []
	
	for f in os.listdir(qb_bin_dir):
		if f.lower().endswith('.md5'):
			f = os.path.join(qb_bin_dir,f)
			os.rename(f,f[:-4])
			subprocess.call(['tar','-xf',f[:-4],'-C',qb_bin_dir])
		
		elif f.lower().endswith('.tar'):
			f = os.path.join(qb_bin_dir,f)
			print('extracting tar : ' + os.path.basename(f))
			subprocess.call(['tar','-xf',f,'-C',qb_bin_dir])
				
	for f in os.listdir(qb_bin_dir):
		if re.match('(system|vendor|odm)', f, re.IGNORECASE):
			verity_image.append(f)

	for f in verity_image:
		f = os.path.join(qb_bin_dir,f)
		if f.endswith('.lz4'):
			print('decompressing lz4 : ' + os.path.basename(f))
			subprocess.call(['bin/lz4','-d',f, f[:-4]])
			print('decompressing simg : ' + os.path.basename(f))
			subprocess.call(['bin/simg2img',f[:-4], f[:-4] + '.raw'])
		else:
			print('decompressing simg : ' + os.path.basename(f))
			subprocess.call(['bin/simg2img',f, f + '.raw'])
	
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-k", "--klog", help="kernel log to be analyzed")
	parser.add_argument("-i", "--image", help="image file to be analyzed")
	parser.add_argument("-p", "--plm", help="PLM id")
	args = parser.parse_args()
	
	#klog, image, summary
	klog=''
	image=''
	need_decompress = True
	need_download = False
	if args.klog:
		klog = args.klog
	if args.image:
		image = args.image
	if args.plm:
		report_id = args.plm

	else:
		report_id = None


	if not klog:
		print('no kernel log to analyze')
		sys.exit()
	
#first, parse kernel log for corruption, qbid
	log_parser = LogParser(klog)
	log_parser.parse()

#resolve qbid , report id
	if not os.path.exists('qb_bin'):
		os.mkdir('qb_bin')
	if not os.path.exists('report'):
		os.mkdir('report')
	
	if not image:
		if log_parser.log_info.qbid:
			qbid = log_parser.log_info.qbid
			print ('no image file specifed. qb_id : ' + qbid + ' is found in kernel log.')
			if not qbid in os.listdir('qb_bin'):
				need_download = True

		else:
			print ('no image file to analyze')
			sys.exit(-1)
		
	elif image:
		m = re.search(RE_QB_BIN , image)
		if(m):
			qbid = m.group(2)
		
	if not report_id:
		report_id = time.strftime("%y%m%d_%H%M") + '_' + 'QB' + qbid
	else:
		report_id = report_id + '_' + 'QB' + qbid
#trigger qb download if needed.
	image_dir = os.path.abspath(os.path.join('qb_bin',qbid))
	report_dir = os.path.abspath(os.path.join('report',report_id))

	if not os.path.exists(image_dir):
		os.mkdir(image_dir)
	if not os.path.exists(report_dir):
		os.mkdir(report_dir)
	
	if need_download:
		print('Downloading binary from QuickBuild server...')
		q = QuickBuild(qbid)
		if not q.run():
			print('qb download has failed. Please check ' + q.url_build + qbid)
			sys.exit(-1)
	elif image:
		print('Specified image will be used : ' + image)
		os.rename(image, image_dir)
	else:
		print('Lucky! Found previously downloaded binary : ' + 'QB' + qbid)

#decompress image
	for f in os.listdir(image_dir):
		if f.endswith('.raw'):
			need_decompress = False

	if need_decompress:
		decompress_qb_bin(image_dir)
	#parse image	
	image_parsers={}
	for f in os.listdir(image_dir):
		if(f.endswith('raw')):
			f=os.path.join(image_dir,f)
			image_parser = ImageParser(f)
			image_parser.read_verity_meta()
			part_name = image_parser.image_info.verity_meta.part_name
			image_parsers[part_name] = image_parser
	
#analyze based on parsed logs and image
	analyzer = Analyzer(log_parser.log_info, image_parsers)
	analyzer.start()

#save report and corrupted/rbs blocks to file
	analyzer.show_report()
	analyzer.save_report_to_file(report_dir)
	analyzer.save_block_to_file(report_dir)
#make symlink to the latest qb_bin, report
	q_latest = os.path.join('qb_bin','latest')
	r_latest = os.path.join('report','latest')
	
	if os.path.exists(q_latest):
		os.remove(q_latest)
	if os.path.exists(r_latest):
		os.remove(r_latest)
	
	os.rename(klog, os.path.join(report_dir,klog))	
	os.symlink(image_dir,os.path.join('qb_bin','latest'))
	os.symlink(report_dir,os.path.join('report','latest'))

if __name__ == "__main__":
	main()
