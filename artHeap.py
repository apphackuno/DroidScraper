# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Heap Module
"""

#-- Import --#
import artParse as art
import artClass as cls
import artField as fld
import artDex as dx
import artJVM as jvm
from utils import * 
#-- End Import --#

class android_heap():

	def readPointer(self, nPath, rAddr,index):
		k = open(nPath, 'rb')
		k.seek(rAddr + index)
		addr = hex(unpack_addr(k))
		k.close()
		return addr

	def readInt(self, nPath, rAddr,index):
		k = open(nPath, 'rb')
		k.seek(rAddr + index)
		addr = unpack_int(k)
		k.close()
		return addr	
	
	def getHeap(self, nPath, rAddr, memList):
		index = get_index('Runtime', 'heap_')
		heapAddr = self.readPointer(nPath, rAddr,index)
		#print "Heap Offset "+ heapAddr
		[heapPath, offset] = art.getOffset(heapAddr, memList)
		return [heapPath, offset]
			
	def getTLAB(self, t,memList):
		[tpath, offset] = art.getOffset(t, memList)	
		with open(tpath, 'rb') as g:
			tlsIndex = get_index('Thread', 'tlsPtr_')
			tidIndex = get_index('tls_ptr_sized_values', 'thread_local_start') + tlsIndex
			g.seek(offset+tidIndex)
			TLAB_str = hex(unpack_addr(g))
			TLAB_top = hex(unpack_addr(g))
			TLAB_end = hex(unpack_addr(g))
			TLAB_lmt = hex(unpack_addr(g))
			TLAB_ObjCount = unpack_addr(g)
			g.close()
			return [TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount]
	
	def getBitmap(self, regionSPath, offset, memList):
		mark_bitmap_index = get_index('RegionSpace', 'mark_bitmap_')
		mark_bitmap = self.readPointer(regionSPath, offset,mark_bitmap_index) #GetLiveBitmap for region space returns mark_bitmap
		#print "live_bitmap " + mark_bitmap #GetLiveBitmap for region space returns mark_bitmap
		[bitmapPath, offset] = art.getOffset(mark_bitmap, memList)
		g = open(bitmapPath, 'rb')
		g.seek(offset)
		########## GET indexes in SpaceBitmap structure
		memmap = hex(unpack_addr(g))
		begin_ = hex(unpack_addr(g))
		bitmap_size_ = unpack_addr(g)
		#print "Bitmap size = "+ str(bitmap_size_)
		heapBegin_ = hex(unpack_addr(g))
		# name_index = get_index('SpaceBitmap', 'name_')

		# name_ = art.getNames(hex(int(mark_bitmap, 16)+name_index), memList)
		#print memmap, begin_, bitmap_size_, heapBegin_, name_
		g.close()
		return [bitmap_size_, heapBegin_]
	
	def getRegion(self, nPath, rAddr, memList):
		[heapPath, offset] = self.getHeap(nPath, rAddr, memList)
		region_space_index = get_index('Heap', 'region_space_')
		regionSpace = self.readPointer(heapPath, offset,region_space_index)
		#print "RegionSpace Offset "+ regionSpace
		[regionSPath, offset] = art.getOffset(regionSpace, memList)
		#live_bitmap = self.readPointer(regionSPath, offset,40) #Don't use always zero
		#print "live_bitmap" + live_bitmap
		#mark_bitmap = self.readPointer(regionSPath, offset,164) #GetLiveBitmap for region space returns mark_bitmap
		#print "mark_bitmap" + mark_bitmap
		num_regions_index = get_index('RegionSpace', 'num_regions_')
		num_regions_ = self.readInt(regionSPath, offset,num_regions_index)	
		# num_non_free_regions_ = self.readInt(regionSPath, offset,104)
		#print "Number of regions = "+ str(num_non_free_regions_)
		regions_index = get_index('RegionSpace', 'regions_')
		regionAddr = self.readPointer(regionSPath, offset,regions_index)
		#print "Number of Regions "+str(num_regions_)
		#print "Number of Non Free Regions "+ str(num_non_free_regions_)
		#print "Region Array Offset "+str(regionAddr)
		#print "Region live_bitmap Offset "+str(mark_bitmap)
		[bitmap_size_, heapBegin_] = self.getBitmap(regionSPath, offset, memList)
		return [regionAddr, num_regions_, bitmap_size_, heapBegin_]
		

#Need to process live_bitmap if livebytes !=-1 or livebytes != (top-pos)
#To write code that checks GetLiveBitmap()->VisitMarkedRange(pos, top, ...) Line253 regions_space-inl.h
	def regionHdr(self, regionAddr, num_regions_, memList):
		[regPath, offset] = art.getOffset(regionAddr, memList)
		g = open(regPath, 'rb')
		g.seek(offset)
		count = 0
		TLAB = []
		NonTLAB =[]
		oCount=0
		state_index = get_index('Region', 'state_')
		isTLAB_index = get_index('Region', 'is_a_tlab_')
		begin_index = get_index('Region', 'begin_')
		top_index = get_index('Region', 'top_')
		end_index = get_index('Region', 'end_')
		livebytes_index = get_index('Region', 'live_bytes_')
		threadpos_index = get_index('Region', 'thread_')
		objalloc_index = get_index('Region', 'objects_allocated_')
		region_sz = get_class_size('Region')
		while (count<num_regions_):
			regBegin = g.tell()
			g.seek(regBegin + state_index)
			state_ = unpack_b(g)
			#g.seek(regBegin+17)
			#type = struct.unpack("<B", g.read(1))[0]
			#print "Region Type "+str(type)
			if(state_ > 0): # non-free region state_=1 means kRegionStateAllocated, our none-free regions are type = 3 (kRegionTypeToSpace), 4 (kRegionTypeNone)
				g.seek(regBegin + isTLAB_index)
				is_a_tlab_ = unpack_bool(g)

				g.seek(regBegin)
				idx = unpack_addr(g) # size_t

				g.seek(regBegin + begin_index)
				begin_ = hex(unpack_addr(g))

				g.seek(regBegin + top_index)
				top_ = hex(unpack_addr(g))

				g.seek(regBegin + end_index)
				end_ = hex(unpack_addr(g))
				#for debug to be removed #Android 8 /art/runtime/gc/space/region_space-inl.h line 249
				g.seek(regBegin + livebytes_index)
				liveBytes = unpack_addr(g)
				diff = int(top_, 16) - int(begin_, 16)
				need_bitmap = liveBytes != -1 and liveBytes != diff
					
				if is_a_tlab_:
#print "Tlab "+str(need_bitmap)
					#end debug
					g.seek(regBegin + threadpos_index)
					thread = hex(unpack_addr(g))
					TLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+str(need_bitmap)+"("+str(liveBytes)+" "+str(diff)+")"+"\t\t\t"+thread)
				else:
					g.seek(regBegin + objalloc_index)
					objAlloc = unpack_addr(g)
					oCount=oCount+objAlloc
					
					#print "NonTlab "+str(need_bitmap)
					#end debug
					NonTLAB.append(str(idx) + "\t"+begin_+"\t"+top_+"\t"+end_+"\t"+str(objAlloc)+"\t"+str(need_bitmap)+"("+str(liveBytes)+" "+str(diff)+")")
			g.seek(regBegin + region_sz)
			count += 1	
		g.close()
		print "NonTlab Total "+str(oCount)
		return [TLAB, NonTLAB]
    	
	def getObjects(self, addrStart, objCount, jvm, lstList, mapList, bitmap_size_, heapBegin_):
		#heapBegin_ = int(heapBegin_, 16)
		[start, end] = art.getSE(lstList)
		objCount = int(objCount)
		[aPath, offset] = art.getOffset(addrStart, mapList)
		addr = open(aPath, 'rb')
		addr.seek(offset)
		#obj = int(addrStart, 16)
		while (objCount>0):	
			#self.get_open_fds()
			try:
				oClass = hex(unpack_uint(addr))
				if (start <= int(oClass, 16) <= end): # validating class pointer needs to edit
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
		addr = open(aPath, 'rb')
		addr.seek(offset)
		oClass = hex(unpack_uint(addr))
		if (start <= int(oClass, 16) <= end):
			off = addr.tell()-4
			objSize, ret = jvm2.dumpRefs(oClass, addr, off)	
		addr.close()
		return ret