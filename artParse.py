#!/usr/bin/python

"""
@author: Aisha Ali-Gombe
@contact: aaligombe@towson.edu
"""


import art_types as types
import sys, os, subprocess, struct,binascii
from collections import OrderedDict





listing= OrderedDict()
memList= OrderedDict()
mapList= OrderedDict()
path = ""
lstList=""
def parseFile(lstFile): #Read mfetch.lst for the beginning of art file
	if (os.path.isfile(lstFile)):
		f= open(lstFile,"r")
		lstList = f.read().split(os.linesep + os.linesep)
		lstList.remove(lstList[0])
		lstList.remove(lstList[len(lstList)-1])
		return lstList

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
		addRange = [j for j in entry.split() if ("0x") in j]
		start = addRange[0]
		end = addRange[1]
		listing.update({entry.split()[1]:addRange})
	return listing

def getLibART(bss, instance): #search for libart.so
	print instance
	insAddr =0;
	if ("[anon:.bss]") in bss: 
		addRange = [j for j in bss.split() if ("0x") in j]
		start = addRange[0]
		end = addRange[1]
		insAddr = int("0x"+instance[len(instance)-4:], 16) -  int("0x"+start[len(start)-4:], 16)
	return insAddr

def lstPath(path, entry):	
	entryPath = path+"/"+entry.split()[1]
	return entryPath[:len(entryPath)-1]


def findAddr(addr, lst):
	addrInt = int(addr, 16)
	start =0
	end=0
	for key, value in lst.items():
		v1 = int(value[1], 16)
		v0 = int(value[0], 16)
		if addrInt < v1:
			if addrInt in xrange(v0, v1):
				start = value[0]
				end =  value[1]
				break
	return [addr, start, key[:len(key)-1]]
	
		
def getRuntime(path): #Get runtime instance 
	libart = [filename for filename in os.listdir(path) if filename.startswith("libart.so")][0]
	process = subprocess.check_output("nm -aS "+path+"/"+libart+" | grep \"_ZN3art7Runtime9instance_E\"", shell = True)
	return process.split()[0] 
	
def getBss(lstList, path):#get bss section and search for runtime instance
	libRange = [i for i in lstList if ("MAPPED FROM: /system/lib/libart.so") in i]
	return lstList[lstList.index(libRange[2])+1]
	
def getOffset(a, alist):
	[addr, start, key] = findAddr(a, alist)
	if (start !=0):
		offset = int(addr, 16) -  int(start, 16)
		aPath = path+"/"+key
	else:
		offset = 0
		aPath = None
	return [aPath, offset]
	
def runtimeObj(rPath, bss, instance, memList):
	with open(rPath, 'rb') as g:
		#g.seek(getLibART(bss, instance)) --- to fix this function, extract last three digit from the runtime instance address - 0070a980
		g.seek(int(hex(0x980), 16))
		runtime = hex(struct.unpack("<I", g.read(4))[0])
		#print "Runtime Address is @ "+ runtime
		[nPath, rAddr] = getOffset(runtime, memList)
		return [runtime, nPath, rAddr]	

def getFhandle(f):
	fhandle =  open(f, 'rb')
	return fhandle		
		
def main(projPath):
	path = projPath
	instance = getRuntime(path)
	lst = [filename for filename in os.listdir(path) if filename.endswith("lst")][0]
	lstFile = path+"/"+lst
	#lstFile = path+"/mfetch.lst"
	lstList = parseFile(lstFile)
	listing = getAddrRange(lstList)
	[memList.update({key:value}) for key, value in listing.items() if key.startswith("mem")]	
	[mapList.update({key:value}) for key, value in listing.items() if key.startswith("map")]
#mapList= OrderedDict()
#[mapList.update({key:value}) for key, value in listing.items() if key.startswith("map")]
	bss = getBss(lstList, path)
	[runtime, nPath, rAddr] = runtimeObj(lstPath(path, bss), bss, instance, memList)
	return[nPath, rAddr, memList, mapList,listing, lstList, runtime]

def readString(dPath, dOff, size):
	g = open(dPath, 'r')
	g.seek(dOff)
	dPointer = g.read(size)
	return dPointer	

def getNames(strPointer, memList):
	[sPath, sOff] = getOffset(strPointer, memList)
	with open(sPath, 'rb') as f:
		f.seek(sOff+4)
		size = struct.unpack("<i", f.read(4))[0]
		dPointer = hex(struct.unpack("<I", f.read(4))[0])
		[dPath, dOff] = getOffset(dPointer, memList)
		dPointer = readString(dPath, dOff, size)
		return dPointer
		
def getStringClass(strOff, i):
	prettyName=''
	i.seek(strOff+8)
	count = struct.unpack("<i", i.read(4))[0]
	len = count >> 1
	if (len >0):
		i.seek(i.tell()+4)
		prettyName = i.read(len)
	return prettyName

def getIndex(Obj, member):
	index = types.art_types.get(Obj)[1].get(member)[0]
	return index
		
def getHeap(nPath, rAddr):
	index = getIndex('Runtime', 'heap_')
	heapOff = rAddr + index
	f = getFhandle(nPath)
	f.seek(heapOff)
	heapAddr = hex(struct.unpack("<I", f.read(4))[0])
	return heapAddr
	
def fromPointer(pointer, list):
	[objPath, objOff] = getOffset(pointer, list)
	if objPath == None:
		g= None
	else:
		g = getFhandle(objPath)
	return [g, objOff]
	
def getRefs(table_begin, segment_state):
	refs = []
	[f, refOff] = fromPointer(table_begin, mapList)
	counter =0
	while (counter < segment_state):
		serial = struct.unpack("<i", f.read(4))[0]
		refOff = f.tell()
		f.seek(refOff + serial*4)
		reference = hex(struct.unpack("<I", f.read(4))[0])
		if(int(reference, 16)>0):
			refs.append(reference)
		counter+=1;
		f.seek(refOff+12)
	return refs
	
def helper(hp, th, nPath, rAddr, path, memList):	
	[regionAddr,num_regions_] = hp.getRegion(nPath, rAddr, memList)	
	[TLAB, NonTLAB] = hp.regionHdr(regionAddr,num_regions_, memList)
	threads = th.__main__(nPath, rAddr, path, memList)
	return [TLAB, NonTLAB, threads]

