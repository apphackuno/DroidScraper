"""
@author: Aisha Ali-Gombe
@contact: aaligombe@towson.edu
"""

import artParse as art
import art_types as types
import sys, os, subprocess, struct,binascii
from collections import OrderedDict

unpack_int = struct.Struct('<I').unpack
unpack_dec = struct.Struct('<i').unpack
unpack_b = struct.Struct('<B').unpack #Byte or Bool
unpack_char = struct.Struct('<c').unpack
unpack_short = struct.Struct('<H').unpack
unpack_float = struct.Struct('<f').unpack
unpack_long = struct.Struct('<Q').unpack
unpack_double = struct.Struct('<d').unpack

class android_threads():

	def getTLPointer(self, nPath, rAddr):
		k = art.getFhandle(nPath)
		index = types.art_types.get('Runtime')[1].get('thread_list_')[0]
		k.seek(rAddr + index)
		TLPointer = hex(unpack_int(k.read(4))[0])
		k.close()
		return TLPointer

	#get list head, tail and size	
	def getTData(self, tAddr, path, memList):
		[addr, start, key] = art.findAddr(tAddr, memList)
		listOff= int(addr, 16) -  int(start, 16)
		tPath = path+"/"+key
		index = types.art_types.get('ThreadList')[1].get('list_')[0]
		listAddr = hex(int(addr, 16) +index)	
		with open(tPath, 'rb') as g:
			g.seek(listOff + index)
			th = hex(unpack_int(g.read(4))[0])
			tt = hex(unpack_int(g.read(4))[0])
			ts = unpack_dec(g.read(4))[0]
			g.close()
		return [listAddr, th,tt,ts]	


	def procThread(self,listAddr, memList):
		[npath, offset] = art.getOffset(listAddr, memList)
		with open(npath, 'rb') as g:
			g.seek(offset)
			p1 = hex(unpack_int(g.read(4))[0])
			p2 = hex(unpack_int(g.read(4))[0])
			p3 = hex(unpack_int(g.read(4))[0])
			g.close()
		return [p1,p2,p3]

	#get the thread pointers - head, tail and size
	def getTpointers(self, listAddr, th, tt, ts, path, memList):
		tList=[]
		counter =0;	
		origTT = tt
		flag = 0
		while (counter < ts):
			counter+=1	
			if (th==tt):
				th = origTT
				flag =1
			if (flag==1): # the thread tail becomes the head
				listAddr =th
				[tt,th,tp] = self.procThread(th, memList)
				tList.append(tp)
			else:
				listAddr =th
				[th,tt,tp] = self.procThread(th, memList)
				tList.append(tp)
		return tList	


	def getThreads(self, tList, memList):
		threads = OrderedDict()
		opeer=[]
		for t in tList:
			[tpath, offset] = art.getOffset(t, memList)	
			with open(tpath, 'rb') as g:
				tls32Index = types.art_types.get('Thread')[1].get('tls32_')[0]
				tidIndex = types.art_types.get('struct_tls32_')[1].get('tid')[0] + tls32Index
				g.seek(offset+tidIndex)
				tid = unpack_dec(g.read(4))[0]
				tlsPtrIndex = types.art_types.get('Thread')[1].get('tlsPtr_')[0]
				nameIndex = tlsPtrIndex + types.art_types.get('struct_tlsPtr_')[1].get('name')[0]
				g.seek(offset+nameIndex)
				strPointer = hex(unpack_int(g.read(4))[0])
				sIndex = tlsPtrIndex + types.art_types.get('struct_tlsPtr_')[1].get('opeer')[0]
				g.seek(offset+sIndex)
				tInstance = hex(unpack_int(g.read(4))[0])
				dPointer = art.getNames(strPointer, memList)
				threads.update({t:[tid, dPointer,strPointer]})
				opeer.append(tInstance)
				g.close()
		return [threads, opeer]
	
		
	def __main__(self,nPath, rAddr, path, memList):				
		tAddr = self.getTLPointer(nPath, rAddr)
		[listAddr,th,tt,ts] = self.getTData(tAddr, path, memList)
		tList = self.getTpointers(listAddr, th, tt, ts, path, memList)
		[threads, opeer] = self.getThreads(tList, memList)
		return [threads, opeer]
		
	def fromMon(self, mAddr, mapList, memList):
		tList=[]
		[mPath, offset] = art.getOffset(mAddr, mapList)	
		print mPath, offset
		with open(mPath, 'rb') as g:
			t = types.art_types.get('Monitor')[1].get('owner')[0]
			print t
			tList.append(t)
			threads = self.getThreads(tList, memList)
			mPath.close()
			return threads
		
		
		
		
		