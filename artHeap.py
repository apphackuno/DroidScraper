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

unpack_int = struct.Struct('<I').unpack
unpack_dec = struct.Struct('<i').unpack
unpack_b = struct.Struct('<B').unpack #Byte or Bool
unpack_char = struct.Struct('<c').unpack
unpack_short = struct.Struct('<H').unpack
unpack_float = struct.Struct('<f').unpack
unpack_long = struct.Struct('<Q').unpack
unpack_double = struct.Struct('<d').unpack

class android_heap():

	def readPointer(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = hex(unpack_int(k.read(4))[0])
		k.close()
		return addr

	def readBool(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = struct.unpack("<?", k.read(1))[0]
		k.close()
		return addr

	def readInt(self, nPath, rAddr,index):
		k = art.getFhandle(nPath)
		k.seek(rAddr + index)
		addr = unpack_dec(k.read(4))[0]
		k.close()
		return addr	
	
	def getHeap(self, nPath, rAddr, memList):
		index = art.getIndex('Runtime', 'heap_')
		heapAddr = self.readPointer(nPath, rAddr,index)
		#print "Heap Offset "+ heapAddr
		[heapPath, offset] = art.getOffset(heapAddr, memList)
		return [heapPath, offset]
			
	def getTLAB(self, t,memList):
		[tpath, offset] = art.getOffset(t, memList)	
		with open(tpath, 'rb') as g:
			tlsIndex = types.art_types.get('Thread')[1].get('tlsPtr_')[0]
			tidIndex = types.art_types.get('struct_tlsPtr_')[1].get('thread_local_start')[0] + tlsIndex
			g.seek(offset+tidIndex)
			TLAB_str = hex(unpack_int(g.read(4))[0])
			TLAB_top = hex(unpack_int(g.read(4))[0])
			TLAB_end = hex(unpack_int(g.read(4))[0])
			TLAB_lmt = hex(unpack_int(g.read(4))[0])
			TLAB_ObjCount = unpack_dec(g.read(4))[0]
			g.close()
			return [TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount]
	
	def getBitmap(self, regionSPath, offset, memList):
		mark_bitmap = self.readPointer(regionSPath, offset,164) #GetLiveBitmap for region space returns mark_bitmap
		#print "live_bitmap " + mark_bitmap #GetLiveBitmap for region space returns mark_bitmap
		[bitmapPath, offset] = art.getOffset(mark_bitmap, memList)
		g = art.getFhandle(bitmapPath)
		g.seek(offset)
		memmap = hex(unpack_int(g.read(4))[0])
		begin_ = hex(unpack_int(g.read(4))[0])
		bitmap_size_ = unpack_dec(g.read(4))[0]
		#print "Bitmap size = "+ str(bitmap_size_)
		heapBegin_ = hex(unpack_int(g.read(4))[0])
		name_ = art.getNames(hex(int(mark_bitmap, 16)+16), memList)
		#print memmap, begin_, bitmap_size_, heapBegin_, name_
		g.close()
		return [bitmap_size_, heapBegin_]
	
	def getRegion(self, nPath, rAddr, memList):
		[heapPath, offset] = self.getHeap(nPath, rAddr, memList)
		regionSpace = self.readPointer(heapPath, offset,460)
		#print "RegionSpace Offset "+ regionSpace
		[regionSPath, offset] = art.getOffset(regionSpace, memList)
		#live_bitmap = self.readPointer(regionSPath, offset,40) #Don't use always zero
		#print "live_bitmap" + live_bitmap
		#mark_bitmap = self.readPointer(regionSPath, offset,164) #GetLiveBitmap for region space returns mark_bitmap
		#print "mark_bitmap" + mark_bitmap
		num_regions_ = self.readInt(regionSPath, offset,100)	
		num_non_free_regions_ = self.readInt(regionSPath, offset,104)
		#print "Number of regions = "+ str(num_non_free_regions_)
		regionAddr = self.readPointer(regionSPath, offset,108)
		#print "Number of Regions "+str(num_regions_)
		#print "Number of Non Free Regions "+ str(num_non_free_regions_)
		#print "Region Array Offset "+str(regionAddr)
		#print "Region live_bitmap Offset "+str(mark_bitmap)
		[bitmap_size_, heapBegin_] = self.getBitmap(regionSPath, offset, memList)
		return [regionAddr, num_regions_, bitmap_size_, heapBegin_]
		
		
	def hasAddress(self, obj, bitmap_size_, heapBegin_):
		offset = obj - heapBegin_
		index = art.OffsetToIndex(offset)
		return index < bitmap_size_ / 4

#Need to process live_bitmap if livebytes !=-1 or livebytes != (top-pos)
#To write code that checks GetLiveBitmap()->VisitMarkedRange(pos, top, ...) Line253 regions_space-inl.h
	def regionHdr(self, regionAddr, num_regions_, memList):
		[regPath, offset] = art.getOffset(regionAddr, memList)
		g = art.getFhandle(regPath)
		g.seek(offset)
		count = 0
		TLAB = []
		NonTLAB =[]
		oCount=0
		while (count<num_regions_):
			regBegin = g.tell()
			g.seek(regBegin+16)
			state_ = struct.unpack("<B", g.read(1))[0]
			#g.seek(regBegin+17)
			#type = struct.unpack("<B", g.read(1))[0]
			#print "Region Type "+str(type)
			if(state_ > 0): # non-free region state_=1 means kRegionStateAllocated, our none-free regions are type = 3 (kRegionTypeToSpace), 4 (kRegionTypeNone)
				g.seek(regBegin+33)
				is_a_tlab_ = struct.unpack("<?", g.read(1))[0]
				if (is_a_tlab_==True):
					g.seek(regBegin)
					idx = unpack_dec(g.read(4))[0]
					begin_ = hex(unpack_int(g.read(4))[0])
					top_ = hex(unpack_int(g.read(4))[0])
					end_ = hex(unpack_int(g.read(4))[0])
					#for debug to be removed #Android 8 /art/runtime/gc/space/region_space-inl.h line 249
					g.seek(regBegin+28)
					liveBytes = unpack_dec(g.read(4))[0]
					diff = int(top_, 16) - int(begin_, 16)
					need_bitmap = liveBytes != -1 and liveBytes != diff
					#print "Tlab "+str(need_bitmap)
					#end debug
					g.seek(regBegin+36)
					thread = hex(unpack_int(g.read(4))[0])
					TLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+str(need_bitmap)+"("+str(liveBytes)+" "+str(diff)+")"+"\t\t\t"+thread)
				else:
					g.seek(regBegin)
					idx = unpack_dec(g.read(4))[0]
					begin_ = hex(unpack_int(g.read(4))[0])
					top_ = hex(unpack_int(g.read(4))[0])
					end_ = hex(unpack_int(g.read(4))[0])
					g.seek(regBegin+20)
					objAlloc = unpack_dec(g.read(4))[0]
					oCount=oCount+objAlloc
					#for debug to be removed
					g.seek(regBegin+28)
					liveBytes = unpack_dec(g.read(4))[0]
					diff = int(top_, 16) - int(begin_, 16)
					need_bitmap = liveBytes != -1 and liveBytes != diff
					#print "NonTlab "+str(need_bitmap)
					#end debug
					NonTLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+str(objAlloc)+"\t"+str(need_bitmap)+"("+str(liveBytes)+" "+str(diff)+")")
					g.seek(regBegin+40)		
			else:
				g.seek(regBegin+40)
			count = count+1	
		g.close()
		print "NonTlab Total "+str(oCount)
		return [TLAB, NonTLAB]
		
	def get_open_fds(self):
		pid = os.getpid()
		procs = subprocess.check_output([ "lsof", '-w', '-Ff', "-p", str(pid)]).split('\n')
		print len(procs)
    	#nprocs = len(filter(lambda s: s and s[ 0 ] == 'f' and s[1: ].isdigit(), procs.split( '\n' ) ))
    	#return nprocs
    	
	def getObjects(self, addrStart, objCount, jvm, lstList, mapList, bitmap_size_, heapBegin_):
		#heapBegin_ = int(heapBegin_, 16)
		[start, end] = art.getSE(lstList)
		objCount = int(objCount)
		[aPath, offset] = art.getOffset(addrStart, mapList)
		addr = art.getFhandle(aPath)
		addr.seek(offset)
		#obj = int(addrStart, 16)
		while (objCount>0):	
			#self.get_open_fds()
			try:
				oClass = hex(unpack_int(addr.read(4))[0])
				if (art.validateAddr(int(oClass, 16), start, end)): # validating class pointer needs to edit
				#if (self.hasAddress(obj+offset, bitmap_size_, heapBegin_)): Validating object pointer to ensure its within heap boundary
					off = addr.tell()-4
					address = hex(start+off)
					objSize = jvm.dumpRefs(oClass, addr, address, off)	
					if (objSize%8!=0):
						objSize = 8*(int(objSize / 8) + (objSize % 8 > 0))
					if (objSize==0):
						objSize =8
					offset+=objSize
					addr.seek(offset)		
				else:
					objSize=8
					offset+=objSize
					addr.seek(offset)
			except:
				objSize=8
				offset+=objSize
				addr.seek(offset)
			objCount=objCount-1			
		addr.close()
	def getObject(self, addrStart, jvm2, lstList, mapList, bitmap_size_, heapBegin_):
		ret =[]
		[start, end] = art.getSE(lstList)
		[aPath, offset] = art.getOffset(addrStart, mapList)
		addr = art.getFhandle(aPath)
		addr.seek(offset)
		oClass = hex(unpack_int(addr.read(4))[0])
		if (art.validateAddr(int(oClass, 16), start, end)):
			off = addr.tell()-4
			objSize, ret = jvm2.dumpRefs(oClass, addr, off)	
		addr.close()
		return ret