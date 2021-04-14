# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Object Decoding Module
"""

#-- Import --#
import artParse as art
import artClass as cls
import artField as fld
import artDex as dx
import artThread as threadlist
import sys
from utils import *
#-- End Import --#

#Dump Libs artJVM.py path -g -data
if os.path.isdir(sys.argv[1]): 
	path = sys.argv[1]
else:
	path = sys.argv[2]
#art.path = path
[nPath, rAddr, memList, mapList, listing, lstList,runtime]=art.main(path)


def getNFPath(name):
	old =name[name.index("-")+1:name.index(".")]
	new = str(int(name[name.index("-")+1:name.index(".")])+1)
	return name.replace(old, new)
	
def getJVMPointer(nPath, rAddr):
	k = open(nPath, 'rb')
	index = get_index('Runtime', 'java_vm_')
	k.seek(rAddr + index)
	ret = hex(unpack_addr(k))
	k.close()
	return ret

def getJVM(jvm, memList):
	[vmPath, offset] = art.getOffset(jvm, memList)
	return [vmPath, offset]

def getIrefTable(vmPath, offset):
	g = open(vmPath, 'rb')
	g.seek(offset)#beginning of the global table
	fsize = os.fstat(g.fileno()).st_size
	off = g.tell()
	if off >= fsize:
		offset = off-fsize
		vmPath = getNFPath(vmPath)
		g = open(vmPath, 'rb')
		g.seek(offset)
	segment_state = unpack_addr(g)
	table_mem_map = hex(unpack_addr(g))
	#print "TableMap "+table_mem_map
	table_begin = hex(unpack_addr(g))
	#print "Irtentry "+table_begin
	ref_kind = unpack_addr(g)
	#print  "ref_kind "+ str(ref_kind)
	max_entries = unpack_addr(g)
	#print  "max entries "+ str(max_entries)
	num_holes = unpack_addr(g)
	#print  "num_holes "+ str(num_holes)
	last_known_state = unpack_uint(g)
	#print  "last_known_state "+ str(last_known_state)
	resizable = hex(unpack_uint(g))
	#print  "resizable "+ resizable
	return [segment_state, table_begin] 


def getGlob(vmPath, offset):
	index = get_index('JavaVMExt', 'globals_')
	gOff = offset+index
	return getIrefTable(vmPath, gOff)
	
def getWeakGlob(vmPath, offset):
	index = get_index('JavaVMExt', 'weak_globals_')
	wOff = offset+index
	return getIrefTable(vmPath, wOff)
	
def getOwner(monitor):
	[g, objOff] = art.fromPointer(monitor, mapList)
	index = get_index('Monitor', 'obj_')
	g.seek(objOff + index)
	ret = hex(unpack_uint(g))
	g.close()
	return ret

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
	g = open(tpath, 'rb')
	g.seek(offset+off)
	newAddr = hex(unpack_addr(g))
	g.close()
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
	index = get_index('JavaVMExt', 'libraries_')
	g = open(vmPath, 'rb')
	g.seek(offset+index)
	libraries_ = hex(unpack_addr(g))
	g.close()
	return libraries_			
		
def getObjectArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(hex(unpack_addr(addr)))
	return arrData	
	
def getCharArray(length_, addr, arrData):
	length_= length_*2
	while (length_ >0):
		arrData.append(unpack_char(addr))
		length_ =length_-1
	return arrData		
def getIntArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(unpack_int(addr))
		length_ =length_-1
	return arrData
def getFloatArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(unpack_float(addr))
		length_ =length_-1
	return arrData
def getShortArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(unpack_ushort(addr))
		length_ =length_-1
	return arrData
def getBArray(length_, addr, arrData):#Byte and Bool
	while (length_ >0):
		arrData.append(unpack_b(addr))
		length_ =length_-1
	return arrData	
def getLongArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(unpack_ulong(addr))
		length_ =length_-1
	return arrData	
def getDoubleArray(length_, addr, arrData):
	while (length_ >0):
		arrData.append(unpack_double(addr))
		length_ =length_-1
	return arrData			
	
def getStringArray(arrSize, i, arrData): #Needs to fix
	while(arrSize >0):
		strPointer = hex(unpack_addr(i))
		if strPointer!="0x0":
			[j, strOff] = art.fromPointer(strPointer, mapList)
			if j:
				arrData.append(art.getStringClass(strOff, j))
				j.close()
		arrSize= arrSize-1
	i.close()
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
	
def getSuperClass(super_class_,fDict, ret):
	superC = True
	while superC:
		[sPath, sOffset] = art.getOffset(super_class_, mapList)
		sAddr = open(sPath, 'rb')
		[name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_] =  cls.getClassMembers(super_class_, sAddr, sOffset, mapList)
		if (name =="java.lang.Object" or super_class_ == None):
			superC = False
		elif ifields_!="0x0":
			ret.append("Super Class Offset " + name)
			fields = fld.getFields(ifields_, mapList)
			for key, values in fields.items():
				fieldIdx = values[2]
				cl,type ,name = dx.getMeta(dexCache,fieldIdx,mapList, memList)
				fDict[values[3]] = [name,type]			
				#print "FieldName - "+name+ " - "+type+" offset "+str(values[3])	
			
def getClsObj(ref, refFile, refOff, fDict, addr, off):
	ret=[]
	[name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_] =  cls.getClassMembers(ref, refFile, refOff, mapList)
	ret.append("Number of Reference Instance Fields = "+str(refSize))
	#print " PrimType "+primType +classFlag
	if(name and name.startswith('[')):
		arrData=[]
		addr.seek(off+8)
		length_ = unpack_int(addr)
		ret.append("length "+str(length_))
		[arrData, length_] = checkArray(name,length_, addr, arrData)
		objSize = 8+4+length_
		ret.append("Object Size " + str(objSize))
		ret.append("The array data for "+name +" is " +str(arrData))
		addr.close()
	elif(name == "java.lang.String"):#&& Its a string
		prettyName=''
		addr.seek(off+8)
		count = unpack_int(addr)
		l = count >> 1
		if l >65536:
			l=0
		if (l >0):
			addr.seek(addr.tell()+4)
			prettyName = addr.read(l)
			ret.append("The data for "+name +" is " +prettyName)
		else:
			ret.append("Null String")
		#print art.getStringClass(off, addr)
		addr.close()
		objSize = 8+4+4+l
	elif(name):#&& classFlag==kClassFlagNormal
		if(super_class_ and name !="java.lang.Object"):
			getSuperClass(super_class_,fDict, ret)
		if ifields_!="0x0":
			fields = fld.getFields(ifields_, mapList)
			for key, values in fields.items():
				fieldIdx = values[2]
				cl,type ,name1 = dx.getMeta(dexCache,fieldIdx,mapList, memList)			
				#print "FieldName - "+name+ " - "+type+" offset "+str(values[3])
				fDict[values[3]] = [name1,type]
		if (classFlag=="kClassFlagClass"):
			ret.append("Is ClassClass "+name)
			[buf,objSize, sFields, dexCache] = fld.getValueClass(fDict, addr, off)
			ret.append("Class Size " + str(objSize))
			ret.append('\n'.join(buf))
		else:
			ret.append(name+" "+classFlag)
			#+" "+ primType
			#+" "+ ifields_+" "+ methods_+" "+ sfields_+" "+ dexCache
			ret.append("Object Size " + str(objSize))
			if fDict:
				r = fld.getValue(fDict, addr, off)
				[ret.append(i) for i in r]
			else:
				ret.append("No Instance Fields for the object")
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
		ret.append("Object is either null or cannot be dereferenced")
		objSize=8	
	return objSize, ret
			#print fld.getValue(ref, iIndex+values[3], mapList, type)
	'''if sfields_!="0x0":
			print getFields(sfields_)
		if methods_!="0x0":
			print getMethods(methods_)'''
			
def dumpRefs(ref, addr, off):
	ret=[]
	[klass, monitor, refFile, refOff]=cls.getOKlass(ref, mapList)
	ret.append( monitor)
	if klass =='0x0':
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		ret.append( "Invalid address for class")
		ret.append( "\n")
		objSize=8
		return objSize	
	name = cls.resolveName(klass, mapList)
	fDict=OrderedDict()
	objSize=0
	#print name
	if ('java.lang.Class' in name):
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		ret.append( "Reference Class is a Class Instance")
		objSize, r = getClsObj(ref, refFile, refOff,fDict, addr, off)
		[ret.append(i) for i in r]
		ret.append( "\n")
	elif ('java.lang.String' in name):
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		ret.append( "Reference Class is String")
		prettyName=''
		'''addr.seek(off+8)
		count = unpack_dec(addr.read(4))[0]
		l = count >> 1
		if (l >0):
			addr.seek(addr.tell()+4)
			prettyName = addr.read(l)
			print prettyName
		else:
			print "Null String"
		objSize = 8+8+l #8 = object inheritance, 8=count+hash, l = length of string'''
		refFile.seek(refOff+8)
		count = unpack_int(refFile)
		l = count >> 1
		if l >65536:
			l=0
		if (l >0):
			refFile.seek(refFile.tell()+4)
			prettyName = refFile.read(l)
			ret.append( prettyName)
		else:
			ret.append( "Null String")
		refFile.close()
		objSize = 8 #8 = object inheritance, 8=count+hash, l = length of string
		print "\n"
	elif (name and name.startswith('[')):
		#count number of [ and loop through
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		print "Reference Class is an "+ name +" Array "
		arrData=[]
		#[i, arrayObjOff] = art.fromPointer(ref, mapList)
		#addr.seek(off+8)
		refFile.seek(refOff+8)
		arrSize = unpack_int(refFile)
		ret.append( "Array size is "+str(arrSize))
		arrData = checkArray(name,arrSize, refFile, arrData)
		if arrData:
			ret.append( "The array data for "+name +" is " +str(arrData))
		#objSize = 8+4+len(arrData)#8 = object inheritance, 4=position for length of array, len = length of array data
		objSize=8
		refFile.close()
		ret.append( "\n")
	elif (len(name)==1):
		obj = getPrimitive(name, addr)
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		ret.append( "Reference Class is a Primitive")
		ret.append( obj)
		objSize=len(str(obj))
	else:
		ret.append( "++++++++++++++++++++++++++++++++++++++++++++")
		objSize=8
		if ('?' in name):
			ret.append( ref+" Cannot Be Resolved "+ str(objSize))
		else:
			ret.append( ref+" " +name +" "+ monitor)
		ret.append( "\n")
	refFile.close()
	return objSize, ret
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
