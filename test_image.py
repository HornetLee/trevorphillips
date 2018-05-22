#! /usr/local/bin/python3
import os

def main():
	with open ('qb_bin/latest/system.img.raw', 'rb+') as f:
		f.seek(-1024*1024*100 , 2)
		f.write(b'\x01\xb0\x01\xb0\x00\x00\x00\x00')
		f.seek(256, os.SEEK_CUR)
		f.write((265).to_bytes(4,byteorder='little'))
		f.write(b'1 /dev/block/platform/11120000.ufs/by-name/SYSTEM /dev/block/platform/11120000.ufs/by-name/SYSTEM 4096 4096 1046076 1046080 sha256 D6A67407543AFD9446785F8EE0E6161B247B1BABC579CD4B416B052767EB7F6C D6A67407543AFD9446785F8EE0E6161B247B1BABC579CD4B416B052767EB7ABC') 
		f.write(b'\x00'*260)
if __name__ == '__main__':
	main()

