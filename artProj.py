#!/usr/bin/python
"""
@author: Aisha Ali-Gombe
@contact: aaligombe@towson.edu
"""
#Program require libart.so and process maps and memfetch.lst

import sys
import artParse as art

def getRuntime():
	try:
		runtime_ = art.getRuntime(art.path)
		print "_ZN3art7Runtime9instance_E offset = "+ runtime_
		[nPath, rAddr, memList, mapList,listing, lstList,runtime] = art.main(art.path)
		print "Runtime Base Address = "+ runtime
	except:
		print "libart.so not in path"
	
def getThreads():
	threads = th.__main__(nPath, rAddr, path, memList)
	print "Threads \t TID \t Name"
	for key, value in threads.items():
		print key+"\t"+str(value[0])+"\t"+value[1]

def getHeapDump():
	[TLAB, NonTLAB, threads] = art.helper(hp, th, nPath, rAddr, path, memList)
	TotalObject =0
	for x in TLAB:
		y = x[x.rfind("\t")+1:]
		for key, value in threads.items():
			if (y==key):
				[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(key, memList)
				TotalObject = TotalObject+TLAB_ObjCount
				if (TLAB_ObjCount>0):
					hp.getObjects(TLAB_str, TLAB_ObjCount, jvm,lstList, mapList)	
	for x in NonTLAB:
		subStr = x[x.find("\t")+1:]
		NTLAB_str = subStr[:subStr.find("\t")]
		NTLAB_ObjCount = int(subStr[subStr.rfind("\t")+1:])
		if (NTLAB_ObjCount>0):
			TotalObject = TotalObject+NTLAB_ObjCount
			hp.getObjects(NTLAB_str, NTLAB_ObjCount, jvm, lstList, mapList)
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
			decodeObject()
		except Exception, ex:
			print str(ex) +"\nThe option decodeObject requires an additional argument - object offset"		
		
def getAllHeap():
	[TLAB, NonTLAB, threads] = art.helper(hp, th, nPath, rAddr, path, memList)
	print "TLAB Regions"
	print "Index\tBegin\t\tTop\t\tEnd\t\tThread\t\tObjects\t\tTid\tThread_Name"
	for x in TLAB:
		y = x[x.rfind("\t")+1:]
		for key, value in threads.items():
			if (y==key):
				[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(y, memList)
				print x+"\t"+str(TLAB_ObjCount)+"\t\t"+str(value[0])+"\t"+value[1]
	print "Non-TLAB Regions"
	print "Index\tBegin\t\tTop\t\tEnd\t\tObjects"
	print '\n'.join(NonTLAB)
	
def heapTLAB():
	ref = sys.argv[4]
	[TLAB_str, TLAB_top,TLAB_end, TLAB_ObjCount] = hp.getTLAB(ref, memList)
	print "TLAB Starts "+str(TLAB_str)
	print "TLAB Ends "+str(TLAB_end)
	print "TLAB Objects "+str(TLAB_ObjCount)
	if (TLAB_ObjCount>0):
		hp.getObjects(TLAB_str, TLAB_ObjCount, jvm, lstList, mapList)
		
def heapNTLAB():
	sAddr = sys.argv[4]
	objs = int(sys.argv[5])
	hp.getObjects(sAddr, objs, jvm, lstList, mapList)
	
def nonMoving():
	sAddr = sys.argv[4]
	objs = int(sys.argv[5])
	hp.getObjects(sAddr, objs, jvm, lstList, mapList)
	
def decodeObject():
	addr = sys.argv[4]
	print "@ Address "+addr
	hp.getObject(addr, jvm2, lstList, mapList)
	
def help():
	print "Usage: python artProj [Options] Command\n" 

	print "Options:\n"
	print "-h, --help \t list all available options and their default values.\n"
	print "Commands:\n"
	print "Runtime \t Print Prints the Android runtime offset\n"	
	
def usage():
	global th, hp, nPath, rAddr, memList, mapList, listing,lstList,runtime, path, jvm, jvm2
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
		path = sys.argv[1] 		
		if (sys.argv[2]=="Runtime"):#Option to print the Runtime offset
			getRuntime()
		else:
			[nPath, rAddr, memList, mapList, listing,lstList,runtime]=art.main(path)
			th = tSelf.android_threads() # Global Thread Object
			hp = heap.android_heap()	# Global Heap Object
			if (sys.argv[2] == "Threads"): #Option to print threads names and tids
				getThreads()
			elif (sys.argv[2] == "Heap"):#Option to print Heap meta data - offset, regions and number of objects in regions
				getHeap()
			elif (sys.argv[2] == "HeapDump"): #Option to dump ALL Heap data
				getHeapDump()	
			else:
				print "Invalid Option"
			
if __name__ == "__main__":
	print "DroidScraper: A Tool for Android In-Memory Object Recovery and Reconstruction"
	try:
		usage()
	except Exception, ex:
		print ex