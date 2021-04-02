# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Field Recovery Module
"""

#-- Import --#
import artParse as art
import artClass as cls
from time import time
from utils import *
#-- End Import --#

def getFields(ifields_, mapList):
	fields= OrderedDict()
	[g, objOff] = art.fromPointer(ifields_, mapList)
	g.seek(objOff)
	size = unpack_int(g)
	counter=0;

	declaring_class_index = get_index("Field", "declaring_class_")
	access_flags_index = get_index("Field", "access_flags_")
	dex_field_index = get_index("Field", "dex_field_index_")
	offset_index = get_index("Field", "offset_")

	while counter<size:
		#declaring_class_ = hex(struct.unpack("<I", g.read(4))[0])
		declaring_class_ = hex(unpack_uint(g))	
		access_flags_ = unpack_int(g)
		dex_field_index_ = unpack_int(g)
		offset_ =unpack_int(g)
		fields.update({counter:[cls.resolveName(declaring_class_, mapList),access_flags_,dex_field_index_,offset_]})
		counter+=1
	g.close()
	return fields
	
	
	
def getFieldsIdx(ifields_, mapList):
	fields= OrderedDict()
	[g, objOff] = art.fromPointer(ifields_, mapList)
	g.seek(objOff)
	size = unpack_int(g)
	counter=0;
	while counter<size:
		#declaring_class_ = hex(struct.unpack("<I", g.read(4))[0])
		hex(unpack_uint(g))		
		unpack_int(g)
		dex_field_index_ = unpack_int(g)
		offset_ =unpack_int(g)
		fields.update({offset_:dex_field_index_})
		counter+=1
	g.close()
	return fields	
	
def getValue(fDict, tlab, offset):
	ret =[]
	for key, value in sorted(fDict.items(), key=lambda item: item[1]):
		tlab.seek(offset+key)
		name = value[0]
		type_ = value[1]
		ret.append( "FieldName - "+name+ " - "+type_+" offset "+str(key))
		if (len(type_)==1):
			addr = getPrimitive(type_, tlab)
		else:
			addr = hex(unpack_uint(tlab))
		ret.append( "Data --- "+addr)
	return ret	
		
def isResolved(status):
	return (status >= 4 or status == -2)
		
def getValueClass(fDict, tlab, offset):
	sField=0
	classSize = 0
	dexCache=0
	buf =[]
	for key, value in sorted(fDict.items(), key=lambda item: item[1]):
		tlab.seek(offset+key)
		name = value[0]
		type = value[1]
		buf.append("FieldName - "+name+ " - "+type+" offset "+str(key))
		if (name=="sFields"):
			addr = hex(unpack_uint(tlab)) # Might be unpack_addr
			sField = addr
		elif (len(type)==1):
			addr = getPrimitive(type, tlab)
		else:
			addr = hex(unpack_uint(tlab)) # Might be unpack_addr
		buf.append("Data --- "+addr)
		if 	(name=="classSize"):
			classSize = addr
		if (name=="status") and not isResolved(int(addr)):
			print "This class cannot be resolved it is either retired or error"
		if (name=="dexCache"):
			dexCache =addr
	return [buf, classSize, sField, dexCache]
	
		
def getPrimitive(type, tlab):
	if (type=="Z" or type=="B"):
		addr=str(unpack_b(tlab))
	elif (type=="C"):
		addr = str(unpack_char(tlab))
	elif (type=="S"):
		addr = str(unpack_ushort(tlab))
	elif (type=="I"):
		addr = str(unpack_int(tlab))
	elif (type=="F"):
		addr = str(unpack_float(tlab))
	elif (type=="J"):
		addr = str(unpack_ulong(tlab))
	elif (type=="D"):
		addr = str(unpack_double(tlab))
	else:
		addr = ''
	#elif (type=="Ljava/lang/String;"):
		#addr = art.getStringClass(offset+key, tlab)
	return addr

'''def B(tlab):
	return str(unpack_b(tlab.read(1))[0])
	
def C(tlab):
	return str(unpack_char(tlab.read(1))[0])
	
def S(tlab): 
	return str(unpack_short(tlab.read(2))[0])
	
def I(tlab): 
	return str(unpack_dec(tlab.read(4))[0])
	
def F(tlab): 
	return str(unpack_float(tlab.read(4))[0])
	
def J(tlab):
	return str(unpack_long(tlab.read(8))[0])
	
def D(tlab):
	return str(unpack_double(tlab.read(8))[0])
	
def getPrimitive(argument, tlab):
	s = time()
	switcher = {
    	"Z": B, 
    	"B": B,
    	"C": C,
    	"S": S,
    	"I": I,
		"F": F,
		"J": J,
		"D": D,
	}
	func = switcher.get(argument, lambda: "Invalid primitive")(tlab)
	print time()-s
	return func'''
	
