# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Class Module
"""

#-- Import --#
import artParse as art
from utils import *
#-- End Import --#

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
		klass = hex(unpack_uint(g))
		monitor = hex(unpack_uint(g))
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
	nameOff = get_index('Class', 'name_')
	[k, clOff] = art.fromPointer(klass, mapList)
	if k != None:
		k.seek(clOff+nameOff)
		nameOff = hex(unpack_uint(k))
		k.close()
		return nameOff
	else:
		return "0x0"

def getType(g, objOff):
	primTypeOff = get_index('Class', 'primitive_type_')
	g.seek(objOff+primTypeOff)
	primType = unpack_uint(g)
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
	compTypeOff = get_index('Class', 'component_type_')
	g.seek(objOff+compTypeOff)
	compClass = hex(unpack_uint(g))
	#compKlassName = resolveName(compClass, mapList)
	g.close()
	return compClass
	
def getObjectSize(g, objOff, mapList):
	objSizeOff = get_index('Class', 'object_size_')
	g.seek(objOff+objSizeOff)
	objSize = unpack_uint(g)
	#compKlassName = resolveName(compClass, mapList)
	g.close()
	return objSize
	
def getClsFlag(g, objOff):
	clsFlagOff = get_index('Class', 'class_flags_')
	g.seek(objOff+clsFlagOff)
	clsFlag = hex(unpack_uint(g))
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
		fIndex = get_index('Class', 'ifields_')
	else:
		fIndex = get_index('Class', 'sfields_')
	g.seek(objOff+fIndex)
	fields_ = hex(unpack_ulong(g))
	return fields_
	
def getClsMethod(g, objOff):	
	mIndex = get_index('Class', 'methods_')
	g.seek(objOff+mIndex)
	methods_ = hex(unpack_ulong(g))
	return methods_

def getSuperClass(g, objOff):	
	mIndex = get_index('Class', 'super_class_')
	g.seek(objOff+mIndex)
	super_class_ = hex(unpack_uint(g))
	return super_class_
	
def getClsDexCache(g, objOff):	
	dexCacheIdx = get_index('Class', 'dex_cache_')
	g.seek(objOff+dexCacheIdx)
	dexCache = hex(unpack_uint(g))
	#print "dexCache "+ dexCache
	return dexCache
	
def getClassMembers(reference, g, objOff, mapList):
	name = resolveName(reference, mapList)
	primType = getType(g, objOff)
	classFlag = getClsFlag(g, objOff)
	obj = get_index('Class', 'object_size_')
	g.seek(objOff+obj)
	objSize = unpack_uint(g)
	if(name!='Cannot Be Resolved'):
		dexCache = getClsDexCache(g, objOff)	
		ifields_ = getIfields(g, objOff, 'ifields_')
		sfields_ = getIfields(g, objOff, 'sfields_')
		methods_=getClsMethod(g, objOff)
		#classFlag = getClsFlag(g, objOff)
		#primType = getType(g, objOff)
		super_class_ = 	getSuperClass(g, objOff)
		refi = get_index('Class', 'num_reference_instance_fields_')
		g.seek(objOff+refi)
		refSize = unpack_uint(g)
		#print "ref instance size "+str(refSize)
		cls = get_index('Class', 'class_size_')
		g.seek(objOff+cls)
		clsSize = unpack_uint(g)
		ins = get_index('Class', 'reference_instance_offsets_')
		g.seek(objOff+ins)
		#print "instance off "+str(unpack_uint(g))
		#print "Class Size "+ str(clsSize)
		return [name, classFlag, primType, ifields_,methods_, sfields_, dexCache, objSize, refSize, super_class_]
	else:
		return [None, classFlag, primType, None,None, None, None,objSize,0,None]

	