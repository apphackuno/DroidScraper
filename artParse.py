# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Parsing Module and helpful function
"""

#-- Import --#
from utils import * 
import re
#-- End Import --#

listing= OrderedDict()
memList= OrderedDict()
mapList= OrderedDict()
lstList=""
	
def parseFile(lstFile): #Read mfetch.lst for the beginning of art file
	if (os.path.isfile(lstFile)):
		f= open(lstFile,"r")
		lstList = f.read().split(os.linesep + os.linesep)
		lstList.remove(lstList[0])
		lstList.remove(lstList[len(lstList)-1])
		f.close()
		return lstList
		
def parseVolFile(lstFile): #Read volatility.lst for the beginning of art file
	if (os.path.isfile(lstFile)):
		f= open(lstFile,"r")
		lstList = f.readlines()
		lstList.remove(lstList[0])
		lstList.remove(lstList[len(lstList)-1])
		for line in lstList:
			line = line.split()
			addRange = []
			addRange.append(line[1])
			addRange.append(line[2])
			if (len(line)==6):
				name =line[5]
			else:
				name =line[4]
			listing.update({name:addRange})
		del listing["----"]
		return [listing, lstList]

def getSE(lstList):#address start and end
	start = lstList[0]
	end = lstList[len(lstList)-1]
	start = start[start.index("range")+6 :start.index("to")-1]
	end = end[end.index("to")+3 :end.index("(")-1]
	return [int(start, 16), int(end, 16)]	
	
def validateAddr(addr,start, end):	
	if (addr < start or addr > end):
		return False
	else:
		return True
	
		
def getAddrRange(lstList):
	for entry in lstList:
		listing.update({entry.split()[1][:-1]: re.search('[0-9a-f]{8,16}-[0-9a-f]{8,16}', entry).group(0).split('-')})
	return listing

def findAddr(addr, lst):
	addrInt = int(addr, 16)
	start =0
	end=0
	for key, value in lst.items():
		v1 = int(value[1], 16)
		v0 = int(value[0], 16)
		if v0 <= addrInt < v1:
			start = value[0]
			end =  value[1]
			break
	return start, key
	
		
def getRuntime(path): #Get runtime instance 
	libart = [filename for filename in os.listdir(path) if filename.startswith("libart.so")][0]
	process = subprocess.check_output("nm -aS "+path+"/"+libart+" | grep \"_ZN3art7Runtime9instance_E\"", shell = True)
	return process.split()[0] 
	
def getBss(lstList, path, instance):#get bss section and search for runtime instance
	libRange = [i for i in lstList if ("/libart.so") in i] #find all insances of libart in mfetch.lst
	address = [j for j in libRange[0].split() if ("0x") in j] #find begin and end address
	#offset of runtime in bss = libart.so load address + (instance offset+ loadBaseAddress)
	#to get loadBase Address = https://stackoverflow.com/questions/18296276/base-address-of-elf 
	#readelf.py -l /Users/aishacct/Desktop/com.facebook.katana/memory_dump/libart.so
	#LOAD           0x000000 0x0000b000 0x0000b000 0x6f3d38 0x6f3d38 R E 0x1000
	process = subprocess.check_output('readelf --segments '+path+'/libart.so | grep "LOAD" -A1 | grep "R E" -B1', shell=True)
	load_address = int(process.decode('utf-8').split()[2], 16)
	address = int(address[0], 16) + (int(instance, 16) - load_address)  
	return [hex(address)]
	
def getOffset(addr, alist):
	start, key = findAddr(addr, alist)
	if (start !=0):
		offset = int(addr, 16) -  int(start, 16)
		aPath = path+"/"+key
	else:
		offset = 0
		aPath = None
	return [aPath, offset]
	
def runtimeObj(address, memList):
	[rPath,rAddr] = getOffset(address, memList)
	with open(rPath, 'rb') as g:
		g.seek(rAddr)
		runtime = hex(unpack_addr(g))
		[nPath, nAddr] = getOffset(runtime, memList)
		g.close()
		return [runtime, nPath, nAddr]	
		
def main(projPath):
	global path, nPath, rAddr, memList, mapList, listing, lstList,runtime
	path = projPath
	instance = getRuntime(path)
	lst = [filename for filename in os.listdir(path) if filename.endswith("lst")][0]
	lstFile = path+"/"+lst
	if lst=="mfetch.lst": # Its mefetch dump
		lstList = parseFile(lstFile)
		listing = getAddrRange(lstList)
	else:
		[listing, lstList] = parseVolFile(lstFile)# Its linux_dump_map dump from volatility
	[address] = getBss(lstList, path, instance)
	[memList.update({key:value}) for key, value in listing.items() if key.startswith("mem")]	
	[mapList.update({key:value}) for key, value in listing.items() if key.startswith("map")]
	[runtime, nPath, rAddr] = runtimeObj(address, memList)
	return[nPath, rAddr, memList, mapList,listing, lstList, runtime]

def readString(dPath, dOff, size):
	g = open(dPath, 'r')
	g.seek(dOff)
	dPointer = g.read(size)
	g.close()
	return dPointer	

def getNames(strPointer, memList): # Reading std::string
	[sPath, sOff] = getOffset(strPointer, memList)
	with open(sPath, 'rb') as f:
		f.seek(sOff + ARCH//8)
		size = unpack_addr(f)
		dPointer = hex(unpack_addr(f))
		[dPath, dOff] = getOffset(dPointer, memList)
		dPointer = readString(dPath, dOff, size)
		f.close()
		return dPointer
		
def getStringClass(strOff, i):
	prettyName=''
	i.seek(strOff+8)
	count = unpack_int(i)
	length = count >> 1
	if (length >0):
		i.seek(i.tell()+4)
		prettyName = i.read(length)
	i.close()
	return prettyName

def getClsSize(Obj):
	sz = art_types.get(Obj)[0]
	return sz
	
def fromPointer(pointer, list):
	[objPath, objOff] = getOffset(pointer, list)
	if objPath is None:
		g = None
	else:
		g = open(objPath, 'rb')
	return [g, objOff]
	
def getRefs(table_begin, segment_state):
	refs = []
	[f, refOff] = fromPointer(table_begin, mapList)
	counter =0
	while (counter < segment_state):
		serial = unpack_dec(f.read(4))[0]
		refOff = f.tell()
		f.seek(refOff + serial*4)
		reference = hex(unpack_int(f.read(4))[0])
		if(int(reference, 16)>0):
			refs.append(reference)
		counter+=1;
		f.seek(refOff+12)
	f.close()
	return refs
	
def helper(hp, th, nPath, rAddr, path, memList):	
	[regionAddr, num_regions_, bitmap_size_, heapBegin_] = hp.getRegion(nPath, rAddr, memList)	
	#hp.getBitmap(bitmap, memList)
	[TLAB, NonTLAB] = hp.regionHdr(regionAddr,num_regions_, memList)
	[threads, opeer] = th.__main__(nPath, rAddr, path, memList)
	return [TLAB, NonTLAB, threads, bitmap_size_, heapBegin_]

'''def parseFile(lstFile): #Read mfetch.lst for the beginning of art file
	listing= OrderedDict()
	if (os.path.isfile(lstFile)):
		f= open(lstFile,"r")
		lstList = f.readlines()
		lstList.remove(lstList[0])
		lstList.remove(lstList[len(lstList)-1])
		for line in lstList:
			line = line.split()
			addRange = []
			addRange.append(line[1])
			addRange.append(line[2])
			if (len(line)==6):
				name =line[5]
			else:
				name =line[4]
			listing.update({name:addRange})
		del listing["----"]
		return lstList
		
def getSE(lstList):#address start and end
	start = lstList[0]
	end = lstList[len(lstList)-1]
	start = start[start.index("range")+6 :start.index("to")-1]
	end = end[end.index("to")+3 :end.index("
	
	'''
