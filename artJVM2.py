#!/usr/bin/python

import artParse as art
import art_types as types
import artClass as cls
import artField as fld
import artDex as dx
import artThread as threadlist
import sys, os, subprocess, struct,binascii
from collections import OrderedDict
from collections import Counter 


#Dump Libs artJVM.py path -g -data
path = sys.argv[1]
art.path = path
[nPath, rAddr, memList, mapList, listing, lstList,runtime]=art.main(path)


def getNFPath(name):
	old =name[name.index("-")+1:name.index(".")]
	new = str(int(name[name.index("-")+1:name.index(".")])+1)
	return name.replace(old, new)
	
def getJVMPointer(nPath, rAddr):
	k = art.getFhandle(nPath)
	index = art.getIndex('Runtime', 'java_vm_')
	k.seek(rAddr + index)
	return hex(struct.unpack("<I", k.read(4))[0])

def getJVM(jvm, memList):
	[vmPath, offset] = art.getOffset(jvm, memList)
	return [vmPath, offset]

def getIrefTable(vmPath, offset):
	g = art.getFhandle(vmPath)
	g.seek(offset)#beginning of the global table
	fsize = os.fstat(g.fileno()).st_size
	off = g.tell()
	if off >= fsize:
		offset = off-fsize
		vmPath = getNFPath(vmPath)
		g = art.getFhandle(vmPath)
		g.seek(offset)
	segment_state = struct.unpack("<i", g.read(4))[0]
	table_mem_map = hex(struct.unpack("<I", g.read(4))[0])
	#print "TableMap "+table_mem_map
	table_begin = hex(struct.unpack("<I", g.read(4))[0])
	#print "Irtentry "+table_begin
	ref_kind = struct.unpack("<i", g.read(4))[0]
	#print  "ref_kind "+ str(ref_kind)
	max_entries = struct.unpack("<i", g.read(4))[0]
	#print  "max entries "+ str(max_entries)
	num_holes = struct.unpack("<i", g.read(4))[0]
	#print  "num_holes "+ str(num_holes)
	last_known_state = struct.unpack("<i", g.read(4))[0]
	#print  "last_known_state "+ str(last_known_state)
	resizable = hex(struct.unpack("<I", g.read(4))[0])
	#print  "resizable "+ resizable
	return [segment_state, table_begin] 


def getGlob(vmPath, offset):
	index = art.getIndex('JavaVMExt', 'globals_')
	gOff = offset+index
	return getIrefTable(vmPath, gOff)
	
def getWeakGlob(vmPath, offset):
	index = art.getIndex('JavaVMExt', 'weak_globals_')
	wOff = offset+index
	return getIrefTable(vmPath, wOff)
	
def getOwner(monitor):
	[g, objOff] = art.fromPointer(monitor, mapList)
	g.seek(objOff+68)
	return hex(struct.unpack("<I", g.read(4))[0])

#get Globals artJVM.py path -g
#get WeakRefs artJVM.py path -w
def printRefs (refs):
	if refs:
		for ref in refs:
			[klass, monitor, refFile, refOff]=cls.getOKlass(ref, mapList)		
			print ref +" "+ cls.resolveName(klass, mapList) + " "+ monitor

def printLRefs (refs):
	print "There are "+str(len(refs)-1)+" local references in the thread "+str(refs[-1])
	print '\n'.join(refs[:-1])
		
		
def getPointer(addr, off):
	[tpath, offset] = art.getOffset(addr, memList)	
	g = art.getFhandle(tpath)
	g.seek(offset+off)
	newAddr = hex(struct.unpack("<I", g.read(4))[0])
	return newAddr

def getJNI(thread):
	jniOff = 156
	return getPointer(thread,jniOff)
	
def getSelf(jni):
	selfOff = 4
	return getPointer(jni,selfOff)

def getLocals(tpath,offset):	
	localsOff = offset+16
	return getIrefTable(tpath, localsOff)

def getLocal(key, tName, ref):
	jni = getJNI(key)
	[tpath, offset] = art.getOffset(jni, memList)
	[segment_state, table_begin]=getLocals(tpath,offset)
	refs = art.getRefs(table_begin, segment_state)
	if ref in refs:
		return tName		
	else:
		return None
		
def mainRefs(ref):
	segment_state=0
	table_begin =0
	[vmPath, offset] = getJVM(getJVMPointer(nPath, rAddr), memList)
	if (ref=="Globals"):
		[segment_state, table_begin] = getGlob(vmPath, offset)
	else:
		[segment_state, table_begin] = getWeakGlob(vmPath, offset)
	refs = art.getRefs(table_begin, segment_state)
	return refs
		

#get Libs artJVM.py path -libs
#Dump Libs artJVM.py path -d offset -o file	
def getLibsOffset(vmPath, offset):
	index = art.getIndex('JavaVMExt', 'libraries_')
	g = art.getFhandle(vmPath)
	g.seek(offset+index)
	libraries_ = hex(struct.unpack("<I", g.read(4))[0])
	return libraries_
	
def searchRef(ref):
	refs = mainRefs("Globals")
	if ref in refs:
		print ref +" is a Global Reference"
	else:
		refs = mainRefs("NonGlobals")
		if ref in refs:
			print ref +" is a Weak Global Reference"
		else:
			tName = searchRefLocal(ref)
			if tName:
				print ref +" is a Local Global Reference in thread - "+tName
			else:
				print "No reference for "+ref
		#print '\n'.join(refs)
def searchRefLocal(ref):
		threads = threadlist.__main__()
		for key, value in threads.items():
			tName = getLocal(key, value[1], ref)
			if tName:
				return tName
		return None
			
		
def getObjectArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(hex(struct.unpack("<I", addr.read(4))[0]))
		length_ =length_-1
	return arrData	
	
def getCharArray(length_, addr, arrData):
	length_= length_*2
	while (length_ >0):
		arrData.append(struct.unpack("<c", addr.read(1))[0])
		length_ =length_-1
	return arrData		
def getIntArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(struct.unpack("<i", addr.read(4))[0])
		length_ =length_-1
	return arrData
def getFloatArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(struct.unpack("<f", addr.read(4))[0])
		length_ =length_-1
	return arrData
def getShortArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(struct.unpack("<H", addr.read(2))[0])
		length_ =length_-1
	return arrData
def getBArray(length_, addr, arrData):#Byte and Bool
	while (length_ >0):
		arrData.append(struct.unpack("<B", addr.read(1))[0])
		length_ =length_-1
	return arrData	
def getLongArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(struct.unpack("<Q", addr.read(8))[0])
		length_ =length_-1
	return arrData	
def getDoubleArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(struct.unpack("<d", addr.read(8))[0])
		length_ =length_-1
	return arrData			
	
def getStringArray(arrSize, i, arrData): #Needs to fix
	while(arrSize >0):
		strPointer = hex(struct.unpack("<I", i.read(4))[0])
		[j, strOff] = art.fromPointer(strPointer, mapList)
		if j:
			arrData.append(art.getStringClass(strOff, j))
		arrSize= arrSize-1
	return arrData

def getStringArray(arrSize, i, arrData): #Needs to fix
	while(arrSize >0):
		strPointer = hex(struct.unpack("<I", i.read(4))[0])
		[j, strOff] = art.fromPointer(strPointer, mapList)
		if j:
			arrData.append(art.getStringClass(strOff, j))
		arrSize= arrSize-1
	return arrData

def checkArray(name,length_, addr, arrData):
	if('[Ljava.lang.String' in name):
		arrData = getStringArray(length_, addr, arrData)
	elif(name =='[C'):	
		arrData = getCharArray(length_, addr, arrData)
		length_ = length_*2
	elif(name =='[B' or name =='[Z'):	
		arrData = getBArray(length_, addr, arrData)	
	elif(name =='[S'):	
		arrData = getShortArray(length_, addr, arrData)	
		length_ = length_*2
	elif(name =='[I'):	
		arrData = getIntArray(length_, addr, arrData)
		length_ = length_*4
	elif(name =='[L'):	
		arrData = getLongArray(length_, addr, arrData)	
		length_ = length_*8
	elif(name =='[F'):	
		arrData = getFloatArray(length_, addr, arrData)	
		length_ = length_*4
	elif(name =='[D'):	
		arrData = getDoubleArray(length_, addr, arrData)
		length_ = length_*8	
	elif (name.startswith('[L') or name.startswith('[[L')):	
		arrData = getObjectArray(length_, addr, arrData)
		length_ = length_*4
	return [arrData, length_]
	
def getSuperClass(super_class_,fDict):
	superC = True
	while superC:
		[sPath, sOffset] = art.getOffset(super_class_, mapList)
		sAddr = art.getFhandle(sPath)
		[name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_] =  cls.getClassMembers(super_class_, sAddr, sOffset, mapList)
		if (name =="java.lang.Object" or super_class_ == None):
			superC = False
		elif ifields_!="0x0":
			print "Super Class Offset " + name
			fields = fld.getFields(dexCache, ifields_, mapList)
			for key, values in fields.items():
				fieldIdx = values[2]
				cl,type ,name = dx.getMeta(dexCache,fieldIdx,mapList, memList)
				fDict[values[3]] = [name,type]			
				#print "FieldName - "+name+ " - "+type+" offset "+str(values[3])	
			
def getClsObj(ref, refFile, refOff, fDict, addr, off):
	[name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_] =  cls.getClassMembers(ref, refFile, refOff, mapList)
	print "Number of Reference Instance Fields = "+str(refSize)
	#print " PrimType "+primType +classFlag
	if(name and name.startswith('[')):
		arrData=[]
		addr.seek(off+8)
		length_ = struct.unpack("<i", addr.read(4))[0]
		print length_
		[arrData, length_] = checkArray(name,length_, addr, arrData)
		objSize = 8+4+length_
		print "Object Size " + str(objSize)
		print "The array data for "+name +" is " +str(arrData)
	elif(name == "java.lang.String"):#&& Its a string
		prettyName=''
		addr.seek(off+8)
		count = struct.unpack("<i", addr.read(4))[0]
		l = count >> 1
		if (l >0):
			addr.seek(addr.tell()+4)
			prettyName = addr.read(l)
			print "The data for "+name +" is " +prettyName
		else:
			print "Null String"
		#print art.getStringClass(off, addr)
		objSize = 8+4+4+l
	elif(name):#&& classFlag==kClassFlagNormal
		if(super_class_ and name !="java.lang.Object"):
			getSuperClass(super_class_,fDict)
		if ifields_!="0x0":
			fields = fld.getFields(dexCache, ifields_, mapList)
			for key, values in fields.items():
				fieldIdx = values[2]
				cl,type ,name1 = dx.getMeta(dexCache,fieldIdx,mapList, memList)			
				#print "FieldName - "+name+ " - "+type+" offset "+str(values[3])
				fDict[values[3]] = [name1,type]
		if (classFlag=="kClassFlagClass"):
			print "Is ClassClass "+name	
			[buf,objSize] = fld.getValueClass(fDict, addr, off)
			print "Object Size " + str(objSize)
			print '\n'.join(buf)
		else:
			print name+" "+classFlag
			#+" "+ primType
			#+" "+ ifields_+" "+ methods_+" "+ sfields_+" "+ dexCache
			print "Object Size " + str(objSize)
			if fDict:
				fld.getValue(fDict, addr, off)
			else:
				print "No Instance Fields for the object"
		'''if sfields_!="0x0":
			sDict=OrderedDict()
			fields = fld.getFields(dexCache, sfields_, mapList)
			for key, values in fields.items():
				fieldIdx = values[2]
				cl,type ,name = dx.getMeta(dexCache,fieldIdx,mapList, memList)			
				#print "FieldName - "+name+ " - "+type+" offset "+str(values[3])
				sDict[values[3]] = [name,type]
			if sDict:
				fld.getValue(sDict, addr, off)
		else:
			print "No Static Fields for the object"'''
	else:
		print "Object is either null or cannot be dereferenced"
		objSize=8	
	return objSize
			#print fld.getValue(ref, iIndex+values[3], mapList, type)
	'''if sfields_!="0x0":
			print getFields(sfields_)
		if methods_!="0x0":
			print getMethods(methods_)'''
			
def dumpRefs(ref, addr, off, start):
	[klass, monitor, refFile, refOff]=cls.getOKlass(ref, mapList)
	if klass =='0x0':
		print "++++++++++++++++++++++++++++++++++++++++++++"
		print "Invalid address for class"
		print "\n"
		objSize=8
		return objSize	
	name = cls.resolveName(klass, mapList)
	fDict=OrderedDict()
	objSize=0
	#print name
	if ('java.lang.Class' in name):
		print "++++++++++++++++++++++++++++++++++++++++++++"
		print "Reference Class is a Class Instance"
		objSize = getClsObj(ref, refFile, refOff,fDict, addr, off)
		print "\n"
	elif ('java.lang.String' in name):
		print "++++++++++++++++++++++++++++++++++++++++++++"
		print "Reference Class is String"
		prettyName=''
		'''addr.seek(off+8)
		count = struct.unpack("<i", addr.read(4))[0]
		l = count >> 1
		if (l >0):
			addr.seek(addr.tell()+4)
			prettyName = addr.read(l)
			print prettyName
		else:
			print "Null String"
		objSize = 8+8+l #8 = object inheritance, 8=count+hash, l = length of string'''
		refFile.seek(refOff+8)
		count = struct.unpack("<i", refFile.read(4))[0]
		l = count >> 1
		if (l >0):
			refFile.seek(refFile.tell()+4)
			prettyName = refFile.read(l)
			print prettyName
		else:
			print "Null String"
		objSize = 8 #8 = object inheritance, 8=count+hash, l = length of string
		print "\n"
	elif (name and name.startswith('[')):
		#count number of [ and loop through
		print "++++++++++++++++++++++++++++++++++++++++++++"
		print "Reference Class is an "+ name +" Array "
		arrData=[]
		#[i, arrayObjOff] = art.fromPointer(ref, mapList)
		#addr.seek(off+8)
		refFile.seek(refOff+8)
		arrSize = struct.unpack("<i", refFile.read(4))[0]
		print "Array size is "+str(arrSize)
		arrData = checkArray(name,arrSize, refFile, arrData)
		if arrData:
			print "The array data for "+name +" is " +str(arrData)
		#objSize = 8+4+len(arrData)#8 = object inheritance, 4=position for length of array, len = length of array data
		objSize=8
		print "\n"
	elif (len(name)==1):
		obj = getPrimitive(name, addr)
		print "++++++++++++++++++++++++++++++++++++++++++++"
		print "Reference Class is a Primitive"
		print obj
		objSize=len(str(obj))
	else:
		print "++++++++++++++++++++++++++++++++++++++++++++"
		objSize=8
		if ('?' in name):
			print ref+" Cannot Be Resolved "+ str(objSize)
		else:
			print ref+" " +name +" "+ monitor
		print "\n"
	return objSize
	#get class, monitor
		#If primitive render data
		#If Array render
		#Class, get fields and methods and print			
			
	
#if len(sys.argv)==2:
#	refs = mainRefs("Globals")	
#	printRefs (refs)
#elif (sys.argv[2]=="-d"):
#	ref = sys.argv[3]
#	searchRef(ref)
#	objSize = dumpRefs(ref)
	
	
		
		
		#cls.getClsFlag(klass, mapList) +" "+ cls.getType(klass, mapList)
		#if ('java.lang.Class' in name):
		#	[dexCache, classFlag, ifields_,methods_, sfields_, name] = getClassObj(ref, mapList)
		#	print "jClass "+ name
		#	print ifields_ +" "+methods_+" "+sfields_
		#	if ifields_!="0x0":
		#		print getFields(dexCache, ifields_)
			#if sfields_!="0x0":
			#	print getFields(sfields_)
			#if methods_!="0x0":
			#	print getMethods(methods_)
		#elif ('java.lang.String' in name):
		#	stringClassOff= refOff+8
		#	print "jString "
			#getStringClass(stringClassOff, refFile)
		#else:
		#	print "jObect "
		#for i in refs:
			#[klass, monitor]=getOKlass(i)
			#name = resolveName(klass)
			#out[i] = name
			#print i, name
	#return out
			#print i, name
			#if ('java.lang.Class' in name):
				#print "Resolved Class Name is == "+getClassClass(i)
			#print monitor
#	if ('java.lang.String' in name):
#		[fHandle, strOff] = fromPointer(i, mapList)
#		print i
#		print "The data in String == "+getStringClass(strOff, fHandle)
	
	
#print "Reference \t JType"
#for key, value in out.items():
#	print key+"\t"+value

#print getLibsOffset(vmPath, offset)
