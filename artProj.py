#!/usr/bin/python
"""
@author: Aisha Ali-Gombe
@contact: aaligombe@towson.edu
"""
#Program require libart.so and process maps and memfetch.lst

import sys
import artParse as art
from time import time

def getRuntime():
	try:
		runtime_ = art.getRuntime(art.path)
		print "_ZN3art7Runtime9instance_E offset = "+ runtime_
		[nPath, rAddr, memList, mapList,listing, lstList,runtime] = art.main(art.path)
		print "Runtime Base Address = "+ runtime
	except:
		print "libart.so not in path"
	
def getThreads(t):
	[threads, opeer] = th.__main__(nPath, rAddr, path, memList)
	if t=='t':
		print "Threads \t TID \t Name"
		for key, value in sorted(threads.items()):
			print key+"\t"+str(value[0])+"\t"+value[1]
	else:
		print '\n'.join(opeer)
		
def getThreadFromMon(addr):
	threads = th.fromMon(addr, mapList, memList)
	print "Threads \t TID \t Name"
	for key, value in sorted(threads.items()):
		print key+"\t"+str(value[0])+"\t"+value[1]
		
def getHeapDump():
	[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = art.helper(hp, th, nPath, rAddr, path, memList)
	TotalObject =0
	for x in TLAB:
		y = x[x.rfind("\t")+1:]
		for key, value in sorted(threads.items()):
			if (y==key):
				[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(key, memList)
				TotalObject = TotalObject+TLAB_ObjCount
				if (TLAB_ObjCount>0):
					hp.getObjects(TLAB_str, TLAB_ObjCount, jvm,lstList, mapList, bitmap_size_, heapBegin_)	
	for x in NonTLAB:
		subStr = x[x.find("\t")+1:]
		NTLAB_str = subStr[:subStr.find("\t")]
		NTLAB_ObjCount = (int)(x.split("\t")[4])
		#NTLAB_ObjCount = int(subStr[subStr.rfind("\t")+1:])
		if (NTLAB_ObjCount>0):
			TotalObject = TotalObject+NTLAB_ObjCount
			hp.getObjects(NTLAB_str, NTLAB_ObjCount, jvm, lstList, mapList, bitmap_size_, heapBegin_)
	print TotalObject	

def getHeap():
	if len(sys.argv)==3:#Get Regions TLABs and NonTLABs
		getAllHeap()		
	elif (sys.argv[3]=="tlab"):#Works with Heap option to dump Heap Objects in TLAB - requires thread address
		try:
			heapTLAB()
		except Exception, ex:
			print str(ex) +"\nThe option tlab requires an additional argument - thread address"	
	elif (sys.argv[3]=="nontlab"):#Works with Heap option to dump Heap Objects in NonTLAB 
		try:
			heapNTLAB()
		except Exception, ex:
			print str(ex) +"\nThe option nontlab requires two additional arguments - region offset and number of objects to recover"
	elif (sys.argv[3]=="decodeObject"):#Works with Heap option to print decode an Objects - requires Object offset
		try:
			[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = getGlobals()
			print decodeObject(bitmap_size_, heapBegin_)
		except Exception, ex:
			print str(ex) +"\nThe option decodeObject requires an additional argument - object offset"		
		
def getAllHeap():
	[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = art.helper(hp, th, nPath, rAddr, path, memList)
	oCount=0
	print "TLAB Regions"
	print "Index\tBegin\t\tTop\t\tEnd\t\tNeed_bitmap\tThread\t\tObjects\t\tTid\tThread_Name"
	for x in TLAB:
		y = x[x.rfind("\t")+1:]
		for key, value in sorted(threads.items()):
			if (y==key):
				[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(y, memList)
				oCount=oCount+TLAB_ObjCount
				print x+"\t"+str(TLAB_ObjCount)+"\t\t"+str(value[0])+"\t"+value[1]
	print "Non-TLAB Regions"
	print "Index\tBegin\t\tTop\t\tEnd\t\tObjects\tNeed_bitmap"
	print '\n'.join(NonTLAB)
	print "Tlab Total "+str(oCount)
	
def heapTLAB():
	[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = art.helper(hp, th, nPath, rAddr, path, memList)
	ref = sys.argv[4]
	[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(ref, memList)
	print "TLAB Starts "+str(TLAB_str)
	print "TLAB Ends "+str(TLAB_end)
	print "TLAB Objects "+str(TLAB_ObjCount)
	if (TLAB_ObjCount>0):
		hp.getObjects(TLAB_str, TLAB_ObjCount, jvm, lstList, mapList, bitmap_size_, heapBegin_)
		
def heapNTLAB():
	[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = art.helper(hp, th, nPath, rAddr, path, memList)
	sAddr = sys.argv[4]
	objs = int(sys.argv[5])
	hp.getObjects(sAddr, objs, jvm, lstList, mapList, bitmap_size_, heapBegin_)
	
def nonMoving():
	sAddr = sys.argv[4]
	objs = int(sys.argv[5])
	hp.getObjects(sAddr, objs, jvm, lstList, mapList, bitmap_size_, heapBegin_)
	
def getGlobals():
	[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = art.helper(hp, th, nPath, rAddr, path, memList)
	return [TLAB, NonTLAB, threads, bitmap_size_, heapBegin_]


def decodeObject(bitmap_size_, heapBegin_):
	addr = sys.argv[4]
	#print "@ Address "+addr
	ret = hp.getObject(addr, jvm2, lstList, mapList, bitmap_size_, heapBegin_)	
	return "@ Address "+addr+"\n"+ '\n'.join(ret)
	

def getIRefs():
	if (sys.argv[3]=="Globals"):
		print "List of Global References"
		refs = jvm.mainRefs("Globals")
		#if refs:
			#for ref in refs:
				#hp.getObject(ref, jvm2, lstList, mapList)
		if (len(sys.argv) <=4):
			jvm.printRefs(refs, lstList, mapList)
		else:
			jvm.printRefs(refs, lstList, mapList)
	elif (sys.argv[3]=="Weak"):
		print "List of Weak Global References"
		refs = jvm.mainRefs("NonGlobals")
		jvm.printRefs(refs, lstList, mapList)
	elif (sys.argv[3]=="Locals"):
		print "List of Local References"
		[threads, opeer] = th.__main__(nPath, rAddr, path, memList)
		jni.__main_(threads)
	elif (sys.argv[3]=="GCRoot"):
		refs = jvm.mainRefs("Globals")
		print jvm.findThreadGCRoot(refs, lstList, mapList)
	
def help():
	print "Usage: pypy artProj Command\n" 

	#print "Options:\n"
	#print "-h, --help \t list all available options and their default values.\n"
	print "Available Commands:\n"
	print "Runtime \t Print the ART offset\n"
	print "Threads \t Print print threads names and tids\n"	
	print "Heap\t \t Print Heap offset and regions metadata\n"
	print "HeapDump \t Dump all heap allocations\n"	
	
	
def usage():
	global th, hp, nPath, rAddr, memList, mapList, listing,lstList,runtime, path, jvm, jvm2, jni
	if len(sys.argv) == 2 and sys.argv[1]=="-h":
		help()
	elif len(sys.argv) < 3:
		print "Insufficient arguments. Try -h for usage and command options"
	else:
		import artThread as tSelf
		import artHeap as heap
		import artField as fld
		import artJVM as jvm
		import artJVM2 as jvm2
		from collections import OrderedDict
		import struct
		#import os, subprocess
		#pid = os.getpid()
		#procs = subprocess.check_output([ "lsof", '-w', '-Ff', "-p", str(pid)]).split('\n')
		#print len(procs)
		#system.exit()
		path = sys.argv[1] 		
		if (sys.argv[2]=="Runtime"):#Option to print the Runtime offset
			getRuntime()
		else:
			[nPath, rAddr, memList, mapList, listing,lstList,runtime]=art.main(path)
			th = tSelf.android_threads() # Global Thread Object
			hp = heap.android_heap()	# Global Heap Object
			if (sys.argv[2] == "Threads"): #Option to print threads names and tids
				if len(sys.argv)>3:
					getThreads('o') #print opeer threads
				else:	
					getThreads('t')  #Option to print threads names and tids
			elif (sys.argv[2] == "Heap"):#Option to print Heap meta data - offset, regions and number of objects in regions
				getHeap()
			elif (sys.argv[2] == "HeapDump"): #Option to dump ALL Heap data
				getHeapDump()
			elif (sys.argv[2]=="IndirectRefs"):
				import artJNI as jni
				getIRefs()	
			#elif (sys.argv[2]=="Monitor"):
			#	addr = '0x84f6d4d2'
			#	getThreadFromMon(addr)
			elif (sys.argv[2]=="GetGlobs"):
				[TLAB, NonTLAB, threads, bitmap_size_, heapBegin_] = getGlobals()
				return [threads, hp, bitmap_size_, heapBegin_, nPath, rAddr, memList, mapList, listing,lstList,runtime]
			else:
				print "Invalid Option"
			
if __name__ == "__main__":
	#s = time()
	print "DroidScraper: A Tool for Android In-Memory Object Recovery and Reconstruction"
	#try:
	usage()
	#except Exception, ex:
	#	print ex
	#print time() - s
		
		
		
'''Use profiler to increase accuracy of Droidscraper
Collect HPROF, get object counts compare to droid scraper heapdump the decode
https://developer.android.com/studio/profile/memory-profiler

Get all static objects - possible roots?

#if 0
   /* Code here will NOT be complied. */
#else
   /* Code will be compiled. */
#endif


if (bit_end == 0):
				right_edge = 0;
			else:
				right_edge = bitmap_begin_+index_end
	else:
		right_edge = left_edge
	right_edge = right_edge & (1 << bit_end) - 1
	if (right_edge != 0):
		ptr_base = IndexToOffset(index_end) + heap_begin_
		shift = trailing("{0:32b}".format(right_edge))
		obj = ptr_base + shift * kAlignment
		count.append(hex(obj))
		right_edge = right_edge ^ 1 << shift
		while (right_edge != 0):
			shift = trailing("{0:32b}".format(right_edge))
			obj = ptr_base + shift * kAlignment
			count.append(hex(obj))
			right_edge = right_edge ^ 1 << shift
			
			# and classFlag=="kClassFlagClass" or classFlag=="kClassFlagNormal" or classFlag=="kClassFlagNoReferenceFields"
			
			
99  // Return true iff <obj> is within the range of pointers that this bitmap could potentially cover,
100  // even if a bit has not been set for it.
101  bool HasAddress(const void* obj) const {
102    // If obj < heap_begin_ then offset underflows to some very large value past the end of the
103    // bitmap.
104    const uintptr_t offset = reinterpret_cast<uintptr_t>(obj) - heap_begin_;
105    const size_t index = OffsetToIndex(offset);
106    return index < bitmap_size_ / sizeof(intptr_t);

inline size_t Object::SizeOf() {
373  // Read barrier is never required for SizeOf since objects sizes are constant. Reading from-space
374  // values is OK because of that.
375  static constexpr ReadBarrierOption kReadBarrierOption = kWithoutReadBarrier;
376  size_t result;
377  constexpr auto kNewFlags = static_cast<VerifyObjectFlags>(kVerifyFlags & ~kVerifyThis);
378  if (IsArrayInstance<kVerifyFlags, kReadBarrierOption>()) {
379    result = AsArray<kNewFlags, kReadBarrierOption>()->
380        template SizeOf<kNewFlags, kReadBarrierOption>();
381  } else if (IsClass<kNewFlags, kReadBarrierOption>()) {
382    result = AsClass<kNewFlags, kReadBarrierOption>()->
383        template SizeOf<kNewFlags, kReadBarrierOption>();
384  } else if (GetClass<kNewFlags, kReadBarrierOption>()->IsStringClass()) {
385    result = AsString<kNewFlags, kReadBarrierOption>()->
386        template SizeOf<kNewFlags>();
387  } else {
388    result = GetClass<kNewFlags, kReadBarrierOption>()->
389        template GetObjectSize<kNewFlags, kReadBarrierOption>();
390  }
391  DCHECK_GE(result, sizeof(Object))
392      << " class=" << Class::PrettyClass(GetClass<kNewFlags, kReadBarrierOption>());
393  return result;'''