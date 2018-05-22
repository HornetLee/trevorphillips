#! /usr/bin/python
import os,sys,math,re
import datetime
import argparse

from ds import *
from verity_parse import *
from verity_analyze import *
import subprocess


report_depth = 0

def j(d,f):
	return os.path.join(d, f)


def show_report(report):
	global report_depth
	report_depth = report_depth + 1
	
	sorted_key = sorted(report)
	for key in sorted_key:
		print ('  '*report_depth + '<'+str(key)+'>')
		if report[key] and type(report[key]) is dict:
			show_report(report[key])
		else:
			print ('    '*report_depth + str(report[key]))

	report_depth = report_depth - 1


def show_key(report):

	for key in report:
		print (key)


def show_report2(report):

	for key in sorted(report):
		
		if key.startswith('CORRUPT'):
			print ('\ndm-verity corrupt found in log')
		else:
			print ('\npre-dmverity error found in log')
		print ('<'+ key + '>')
		print ('a.result')
		print (': '+ report[key]['RESULT'])
		print ('b.detail')
		print (': '+report[key]['DETAIL'])
		print ('c.resolution')
		print (': '+report[key]['RESOLUTION'])

			
def show_corrupt(corrupt):
	pass


def show_log_info(log_info):
	pass	


def show_image_info(image_info):
	pass




def main():
	#image_parser = ImageParser('qb_bin/QB1721285/vendor.img.raw')
	#image_parser.read_verity_meta()

	parser = argparse.ArgumentParser()
	parser.add_argument("-k", "--klog", help="kernel log to be analyzed")
	parser.add_argument("-i", "--image", help="image file to be analyzed")
	parser.add_argument("-p", "--plm", help="PLM id")
	
	args = parser.parse_args()

	if args.image:
		print (args.image)
	
	for f in os.listdir('qb_bin/latest'):
		if f.startswith('summary') or f.endswith('.lst') or f.endswith('kmsg'):
			log_parser = LogParser(j('qb_bin/latest',f))
			log_parser.parse()


	raw_files=[]
	image_parsers = {}
	for f in os.listdir('qb_bin/latest'):
		if f.endswith('.raw'):
			image_parser = ImageParser(j('qb_bin/latest', f))
			image_parser.read_verity_meta()
			
			part_name = image_parser.image_info.verity_meta.part_name
			image_parsers[part_name] = image_parser


	analyzer = Analyzer(log_parser.log_info , image_parsers)
	analyzer.save_block_to_file('report/test')
	analyzer.start()
	report = analyzer.get_report()
	show_report2(report)
if __name__ == "__main__":
	main()

