"""
@author: Aisha Ali-Gombe
@contact: aaligombe@towson.edu
"""
import artParse as art
import art_types as types
import artClass as cls
import artField as fld
import artDex as dx
import artJVM as jvm
import sys, os, subprocess, struct,binascii
from collections import OrderedDict

class android_heap():

	def readPointer(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = hex(struct.unpack("<I", k.read(4))[0])
		return addr

	def readBool(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = struct.unpack("<?", k.read(1))[0]
		return addr

	def readInt(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = struct.unpack("<i", k.read(4))[0]
		return addr	
	
	def getHeap(self, nPath, rAddr, memList):
		index = art.getIndex('Runtime', 'heap_')
		heapAddr = self.readPointer(nPath, rAddr,index)
		print "Heap Offset "+ heapAddr
		[heapPath, offset] = art.getOffset(heapAddr, memList)
		return [heapPath, offset]
			
	def getTLAB(self, t,memList):
		[tpath, offset] = art.getOffset(t, memList)	
		with open(tpath, 'rb') as g:
			tlsIndex = types.art_types.get('Thread')[1].get('tlsPtr_')[0]
			tidIndex = types.art_types.get('struct_tlsPtr_')[1].get('thread_local_start')[0] + tlsIndex
			g.seek(offset+tidIndex)
			TLAB_str = hex(struct.unpack("<I", g.read(4))[0])
			TLAB_top = hex(struct.unpack("<I", g.read(4))[0])
			TLAB_end = hex(struct.unpack("<I", g.read(4))[0])
			TLAB_lmt = hex(struct.unpack("<I", g.read(4))[0])
			TLAB_ObjCount = struct.unpack("<i", g.read(4))[0]
			return [TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount]
	
	def getRegion(self, nPath, rAddr, memList):
		[heapPath, offset] = self.getHeap(nPath, rAddr, memList)
		regionSpace = self.readPointer(heapPath, offset,460)
		print "RegionSpace Offset "+ regionSpace
		[regionSPath, offset] = art.getOffset(regionSpace, memList)
		mark_bitmap = self.readPointer(regionSPath, offset,164)
		num_regions_ = self.readInt(regionSPath, offset,100)	
		num_non_free_regions_ = self.readInt(regionSPath, offset,104)
		regionAddr = self.readPointer(regionSPath, offset,108)
		print "Number of Regions "+str(num_regions_)
		print "Number of Non Free Regions "+ str(num_non_free_regions_)
		print "Region Array Offset "+str(regionAddr)
		return [regionAddr, num_regions_]
	


	def regionHdr(self, regionAddr, num_regions_, memList):
		[regPath, offset] = art.getOffset(regionAddr, memList)
		g = art.getFhandle(regPath)
		g.seek(offset)
		count = 0
		TLAB = []
		NonTLAB =[]
		while (count<num_regions_):
			regBegin = g.tell()
			g.seek(regBegin+16)
			state_ = struct.unpack("<B", g.read(1))[0]
			if(state_ > 0):
				g.seek(regBegin+33)
				is_a_tlab_ = struct.unpack("<?", g.read(1))[0]
				if (is_a_tlab_==True):
					g.seek(regBegin)
					idx = struct.unpack("<i", g.read(4))[0]
					begin_ = hex(struct.unpack("<I", g.read(4))[0])
					top_ = hex(struct.unpack("<I", g.read(4))[0])
					end_ = hex(struct.unpack("<I", g.read(4))[0])
					#g.seek(regBegin+28)
					#liveBytes = struct.unpack("<i", g.read(4))[0]
					#print "Tlab "+str(liveBytes)
					g.seek(regBegin+36)
					thread = hex(struct.unpack("<I", g.read(4))[0])
					TLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+thread)
				else:
					g.seek(regBegin)
					idx = struct.unpack("<i", g.read(4))[0]
					begin_ = hex(struct.unpack("<I", g.read(4))[0])
					top_ = hex(struct.unpack("<I", g.read(4))[0])
					end_ = hex(struct.unpack("<I", g.read(4))[0])
					g.seek(regBegin+20)
					objAlloc = struct.unpack("<i", g.read(4))[0]
					#g.seek(regBegin+28)
					#liveBytes = struct.unpack("<i", g.read(4))[0]
					#print "NonTlab "+str(liveBytes)
					NonTLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+str(objAlloc))
					g.seek(regBegin+40)		
			else:
				g.seek(regBegin+40)
			count = count+1	
		return [TLAB, NonTLAB]

	def getObjects(self, addrStart, objCount, jvm, lstList, mapList):
		[start, end] = art.getSE(lstList)
		objCount = int(objCount)
		[aPath, offset] = art.getOffset(addrStart, mapList)
		addr = art.getFhandle(aPath)
		addr.seek(offset)
		while (objCount>0):
			oClass = hex(struct.unpack("<I", addr.read(4))[0])
			if (art.validateAddr(int(oClass, 16), start, end)):
				off = addr.tell()-4
				objSize = jvm.dumpRefs(oClass, addr, off, start)	
				if (objSize%8!=0):
					objSize = 8*(int(objSize / 8) + (objSize % 8 > 0))
				if (objSize==0):
					objSize =8
				offset+=objSize
				addr.seek(offset)		
				objCount=objCount-1	
			else:
				objSize=8
				offset+=objSize
				addr.seek(offset)		

	def getObject(self, addrStart, jvm2, lstList, mapList):
		[start, end] = art.getSE(lstList)
		[aPath, offset] = art.getOffset(addrStart, mapList)
		addr = art.getFhandle(aPath)
		addr.seek(offset)
		oClass = hex(struct.unpack("<I", addr.read(4))[0])
		if (art.validateAddr(int(oClass, 16), start, end)):
			off = addr.tell()-4
			objSize = jvm2.dumpRefs(oClass, addr, off, start)	