import artParse as art
import sys, os, subprocess, struct,binascii
from collections import OrderedDict

name = ""
dexCache = ""	
ifields_ = ""
sfields_ = ""
methods_= ""
classFlag = ""
primType = ""

	
def getOKlass(reference, mapList):
	[g, objOff] = art.fromPointer(reference, mapList)
	if g == None:
		return ['0x0','0x0', None, objOff]
	else:
		g.seek(objOff)
		klass = hex(struct.unpack("<I", g.read(4))[0])
		monitor = hex(struct.unpack("<I", g.read(4))[0])
		return [klass,monitor, g, objOff]
	
def resolveName(klass, mapList):
	name ='Cannot Be Resolved'
	nameOff = getNamePointer(klass, mapList)
	if (int(nameOff, 16)> 0):
		[i, strOff] = art.fromPointer(nameOff, mapList)
		if i == None:
			name ='Cannot Be Resolved'
		else:
			name = art.getStringClass(strOff, i)
			i.close()
	return name	
		
def getNamePointer(klass, mapList):
	nameOff = art.getIndex('Class_Obj', 'name_')
	[k, clOff] = art.fromPointer(klass, mapList)
	if k != None:
		k.seek(clOff+nameOff)
		nameOff = hex(struct.unpack("<I", k.read(4))[0])
		k.close()
		return nameOff
	else:
		return "0x0"

def getType(g, objOff):
	primTypeOff = art.getIndex('Class_Obj', 'primitive_type_')
	g.seek(objOff+primTypeOff)
	primType = struct.unpack("<H", g.read(2))[0]
	typeSwitch = {
		0: "jObject",
		1: "jBoolean",
		2: "jByte",
		3: "jChar",
		4: "jShort",
		5: "jInt",
		6: "jLong",
		7: "jFloat",
		8: "jDouble",
	}
	t = typeSwitch.get(primType, "jObject")
	return t
	
	
	
def getComponent(g, objOff,mapList):
	compTypeOff = art.getIndex('Class_Obj', 'component_type_')
	g.seek(objOff+compTypeOff)
	compClass = hex(struct.unpack("<I", g.read(4))[0])
	#compKlassName = resolveName(compClass, mapList)
	g.close()
	return compClass
	
def getObjectSize(g, objOff, mapList):
	objSizeOff = art.getIndex('Class_Obj', 'object_size_')
	g.seek(objOff+objSizeOff)
	objSize = struct.unpack("<i", g.read(4))[0]
	#compKlassName = resolveName(compClass, mapList)
	g.close()
	return objSize
	
def getClsFlag(g, objOff):
	clsFlagOff = art.getIndex('Class_Obj', 'class_flags_')
	g.seek(objOff+clsFlagOff)
	clsFlag = hex(struct.unpack("<I", g.read(4))[0])
	typeSwitch = {
		"0x0": "kClassFlagNormal",
		"0x1": "kClassFlagNoReferenceFields",
		"0x4": "kClassFlagString",
		"0x8": "kClassFlagObjectArray",
		"0x10": "kClassFlagClass",
		"0x20": "kClassFlagClassLoader",
		"0x40": "kClassFlagDexCache",
		"0x80": "kClassFlagSoftReference",
		"0x100": "kClassFlagWeakReference",
		"0x200": "kClassFlagFinalizerReference",
		"0x400": "kClassFlagPhantomReference",
	}
	t = typeSwitch.get(clsFlag, "kClassFlagNormal")
	return t
	
def getIfields(g, objOff, field):
	fIndex=""
	if (field=='ifields_'):
		fIndex = art.getIndex('Class_Obj', 'ifields_')
	else:
		fIndex = art.getIndex('Class_Obj', 'sfields_')
	g.seek(objOff+fIndex)
	fields_ = hex(struct.unpack("<Q", g.read(8))[0])
	return fields_
	
def getClsMethod(g, objOff):	
	mIndex = art.getIndex('Class_Obj', 'methods_')
	g.seek(objOff+mIndex)
	methods_ = hex(struct.unpack("<Q", g.read(8))[0])
	return methods_

def getSuperClass(g, objOff):	
	mIndex = art.getIndex('Class_Obj', 'super_class_')
	g.seek(objOff+mIndex)
	super_class_ = hex(struct.unpack("<I", g.read(4))[0])
	return super_class_
	
def getClsDexCache(g, objOff):	
	dexCacheIdx = art.getIndex('Class_Obj', 'dex_cache_')
	g.seek(objOff+dexCacheIdx)
	dexCache = hex(struct.unpack("<I", g.read(4))[0])
	#print "dexCache "+ dexCache
	return dexCache
	
def getClassMembers(reference, g, objOff, mapList):
	name = resolveName(reference, mapList)
	primType = getType(g, objOff)
	classFlag = getClsFlag(g, objOff)
	obj = art.getIndex('Class_Obj', 'object_size_')
	g.seek(objOff+obj)
	objSize = struct.unpack("<i", g.read(4))[0]
	if(name!='Cannot Be Resolved'):
		dexCache = getClsDexCache(g, objOff)	
		ifields_ = getIfields(g, objOff, 'ifields_')
		sfields_ = getIfields(g, objOff, 'sfields_')
		methods_=getClsMethod(g, objOff)
		#classFlag = getClsFlag(g, objOff)
		#primType = getType(g, objOff)
		super_class_ = 	getSuperClass(g, objOff)
		refi = art.getIndex('Class_Obj', 'num_reference_instance_fields_')
		g.seek(objOff+refi)
		refSize = struct.unpack("<i", g.read(4))[0]
		#print "ref instance size "+str(refSize)
		cls = art.getIndex('Class_Obj', 'class_size_')
		g.seek(objOff+cls)
		clsSize = struct.unpack("<i", g.read(4))[0]
		ins = art.getIndex('Class_Obj', 'reference_instance_offsets_')
		g.seek(objOff+ins)
		#print "instance off "+str(struct.unpack("<i", g.read(4))[0])
		#print "Class Size "+ str(clsSize)
		return [name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_]
	else:
		return [None, classFlag, primType, None,None, None, None,objSize,0,None]

	