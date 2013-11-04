#
# Hash function setup for Beta Bot
#
# REQUIRES MANUAL SETUP BELOW (see TODO)
#
# This script will build a hash list of all the functions in all DLLs used by
# Beta Bot, and then set the names for all the offsets in the sample.
#
# Beta Bot uses another field to determine the DLL to which the hash
# belongs, but where there's very few collisions this value wasn't used.
#
# There are a few hashes not stored in the table, including:
# * ZwCreateThreadEx
# * KiFastSystemCall
# * KiIntSystemCall
# * GetThreadId
# If you see these or others in the code they can be entered manually.
#
# Requires pefile
# 
from idaapi import *
from idautils import *
from idc import *
import sys
import pefile
import os

# TODO: SET THESE VALUES FOR YOUR SAMPLE:
#
# These follow the shortly after a list of dlls in the .data section.
#
# They are of the format hash:32/offset:32/dword, but IDA will likely
# show them as 8 db and an offset. Convert some of the 8 db into 2 dd
# until you can see the list correctly. The result will look like:
#
# dd 4F2B0775h
# dd offset unk_43E064
# dd 0Ah
#
# dd 0C9250C68H
# dd offset word_43E06C
# dd 0Dh
# ...
#
# start = 0x003785f0
# last = 0x00379d78
start = None
last = None

if not start or not last:
	print "Error: Must set start and last"
	sys.exit(1)

# No configuration required below

# Find location of ntdll.dll in sample, just after
# the Opera/9.00. These DLLs are used by the importer.
dlls = [
	"ntdll.dll",
	"kernel32.dll",
	"secur32.dll",
	"crypt32.dll",
	"user32.dll",
	"advapi32.dll",
	"wininet.dll",
	"shell32.dll",
	"shlwapi.dll",
	"ole32.dll",
	"version.dll",
	"sfc.dll",
	"dnsapi.dll",
	"ws2_32.dll",
	]


sys32 = os.environ['WINDIR'] + "\\System32\\"
def hash_fun(dll_name, fun_name):
	name = dll_name + "." + fun_name

	x = 0
	y = 1
	for letter in name:
		y = (y + ord(letter)) % 0xFFF1
		x = (x + y) % 0xFFF1
	return (x<<16|y)

hashes = {}

for dll_name in dlls:
	dll = pefile.PE(sys32 + dll_name)

	for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
		if export.name:
			h = hash_fun(dll_name, export.name)
			existing = ""
			if h in hashes:
				existing = hashes[h] + "_OR_"
			hashes[h] = existing + "%s"%(export.name)

# These hashes existed in my samples outside the normal list:
for h in [0x860e09f1, 0x856309fa, 0x7bb00997, 0xb30b0b4e, 0x6bf308a4]:
	if h in hashes:
		print "%x -> %s"%(h, hashes[h])

print "start is: " + str(start)

unit = start
while (unit <= last):
	hashv = Dword(unit)
	offset = Dword(unit + 4)
	if hashv in hashes:
		print "SET %x: %s"%(offset, hashes[hashv])
		MakeName(offset, hashes[hashv])
	unit += 12

