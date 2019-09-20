import artParse as art
import artClass as cls
import sys, os, subprocess, struct,binascii
from collections import OrderedDict

def getFields(dexCache, ifields_, mapList):
	fields= OrderedDict()
	[g, objOff] = art.fromPointer(ifields_, mapList)
	g.seek(objOff)
	size = struct.unpack("<i", g.read(4))[0]
	counter=1;
	while counter<=size:
		declaring_class_ = hex(struct.unpack("<I", g.read(4))[0])		
		access_flags_ = struct.unpack("<i", g.read(4))[0]
		dex_field_index_ = struct.unpack("<i", g.read(4))[0]
		offset_ =struct.unpack("<i", g.read(4))[0]
		fields[counter] = [cls.resolveName(declaring_class_, mapList),access_flags_,dex_field_index_,offset_]
		counter+=1
	return fields
	
	
def getValue(fDict, tlab, offset):
	for key, value in fDict.items():
		tlab.seek(offset+key)
		name = value[0]
		type = value[1]
		print "FieldName - "+name+ " - "+type+" offset "+str(key)
		if (len(type)==1):
			addr = getPrimitive(type, tlab)
		else:
			addr = hex(struct.unpack("<I", tlab.read(4))[0])
		print "Data --- "+addr	
		
def getValueClass(fDict, tlab, offset):
	classSize = 0
	buf =[]
	for key, value in fDict.items():
		tlab.seek(offset+key)
		name = value[0]
		type = value[1]
		buf.append("FieldName - "+name+ " - "+type+" offset "+str(key))
		if (len(type)==1):
			addr = getPrimitive(type, tlab)
		else:
			addr = hex(struct.unpack("<I", tlab.read(4))[0])
		buf.append("Data --- "+addr)
		if 	(name=="classSize"):
			classSize = addr
	return [buf,classSize]
	
		
def getPrimitive(type, tlab):
	if (type=="Z" or type=="B"):
		addr = str(struct.unpack("<B", tlab.read(1))[0])
	elif (type=="C"):
		addr = str(struct.unpack("<c", tlab.read(1))[0])
	elif (type=="S"):
		addr = str(struct.unpack("<H", tlab.read(2))[0])
	elif (type=="I"):
		addr = str(struct.unpack("<i", tlab.read(4))[0])
	elif (type=="F"):
		addr = str(struct.unpack("<f", tlab.read(4))[0])
	elif (type=="J"):
		addr = str(struct.unpack("<Q", tlab.read(8))[0])
	elif (type=="D"):
		addr = str(struct.unpack("<d", tlab.read(8))[0])
	#elif (type=="Ljava/lang/String;"):
		#addr = art.getStringClass(offset+key, tlab)
	return addr