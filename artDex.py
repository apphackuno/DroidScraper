# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Dex Module
"""

#-- Import --#
import artParse as art
from utils import * 
#-- End Import --#

def getDex(dexCache, mapList):
	[g, offset] = art.fromPointer(dexCache, mapList)
	dexFileIdx = get_index("DexCache","dex_file_")
	g.seek(offset+dexFileIdx)
	dexFile = hex(unpack_ulong(g))
	#print "dexFile "+dexFile
	loc_ = get_index("DexCache","location_")
	g.seek(offset+loc_)
	loc = hex(unpack_uint(g))
	g.close()
	[g, offset]= art.fromPointer(loc, mapList)
	#print "DexFile Location "+art.getStringClass(offset, g)
	g.close()
	return dexFile

def getIdx(Idxs, idx, dexFile, memList):
	idsOff = hex(int(dexFile,16)+Idxs)
	[g, offset]= art.fromPointer(idsOff, memList)
	g.seek(offset+idx)
	id = hex(idx+ int(idsOff,16))
	g.close()
	return id
		
def getIds(g, offset):
	strIds = get_index("DexFile","string_ids_")	
	g.seek(offset+strIds)
	sIdsOff = hex(unpack_addr(g))
	fieldIds = get_index("DexFile","field_ids_")	
	g.seek(offset+fieldIds)
	fIdsOff = hex(unpack_addr(g))
	methodIds = get_index("DexFile","method_ids_")	
	g.seek(offset+methodIds)
	mIdsOff = hex(unpack_addr(g))
	typeIds = get_index("DexFile","type_ids_")	
	g.seek(offset+typeIds)
	tIdsOff = hex(unpack_addr(g))
	begin = get_index("DexFile","begin_")	
	g.seek(offset+begin)
	beginOff = hex(unpack_addr(g))
	#fieldId = getIdx(fieldIds, fieldIdx, dexFile, memList)	
	return [beginOff,sIdsOff, fIdsOff,mIdsOff,tIdsOff]
	
def getFieldIdx(fIdsOff, dex_field_index_,mapList):
	[g, offset]= art.fromPointer(fIdsOff, mapList)
	g.seek(offset+ (8*dex_field_index_))
	clsIdx = unpack_ushort(g)
	typeIdx = unpack_ushort(g)
	nameIdx = unpack_int(g)
	#typeAddr = hex(int(fIdsOff,16)+dex_field_index_+ get_index("FieldId","type_idx_"))
	#nameAddr = hex(int(fIdsOff,16)+dex_field_index_+ get_index("FieldId","name_idx_"))
	g.close()
	return [clsIdx,typeIdx,nameIdx]
	
'''def getStrIndex(strIdx,dexFile, memList):
	strIds = get_index("DexFile","string_ids_")
	strId = getIdx(strIds, strIdx, dexFile, memList)
	return strId'''

def uleb128_decode(dataIndex, g):
	g.seek(dataIndex)
	result = unpack_b(g)
	if (result > 0x7f):
		cur = unpack_b(g)
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f):
			cur = unpack_b(g)
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f):
				cur = unpack_b(g)
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f):
					cur = unpack_b(g)
					result |= cur << 28;
	g.seek(g.tell())
	data = g.read(result)
	g.close()
	return data
	
def getName(sIdsOff,mapList, nameIdx, beginOff):
	[strHandle, strIdxOdd]= art.fromPointer(sIdsOff, mapList)	
	strHandle.seek(strIdxOdd+4*nameIdx)
	strDataItemOff =  unpack_int(strHandle)
	[bHandle, bOdd]= art.fromPointer(beginOff, mapList)
	strHandle.close()
	return uleb128_decode(bOdd+strDataItemOff, bHandle)
	
def getType(tIdsOff,mapList,typeIdx, beginOff, sIdsOff, clsIdx):
	[tHandle, tIdxOdd]= art.fromPointer(tIdsOff, mapList)	
	tHandle.seek(tIdxOdd+(4*typeIdx))
	descIdx_T =  unpack_int(tHandle)
	type = getName(sIdsOff,mapList, descIdx_T, beginOff)
	tHandle.seek(tIdxOdd+(4*clsIdx))
	descIdx_C =  unpack_int(tHandle)
	cls = getName(sIdsOff,mapList, descIdx_C, beginOff)
	tHandle.close()
	return [type, cls]
	
    
def getMeta(dexCache,dex_field_index_,mapList, memList):
	dexFile = getDex(dexCache, mapList)
	[dexHandle, dexOffset]= art.fromPointer(dexFile, memList)		
	[beginOff, sIdsOff,fIdsOff,mIdsOff,tIdsOff] = getIds(dexHandle,dexOffset)	
	dexHandle.close()
	[clsIdx,typeIdx,nameIdx] = getFieldIdx(fIdsOff, dex_field_index_,mapList)
	name = getName(sIdsOff,mapList, nameIdx, beginOff)
	[type, cls] = getType(tIdsOff,mapList,typeIdx, beginOff, sIdsOff,clsIdx)
	return [cls,type ,name]
	
'''	
def getFieldTypeId(fieldId)
	[g, offset]= art.getOffset(fieldId, memList)	
	g = getFhandle(fPath)
	fieldIdType = get_index("FieldId","type_idx_")
	g.seek(fOff+fieldIdType)
	fTypeId = struct.unpack("<Q", g.read(2))[0]
	return fTypeId
	'''
	
