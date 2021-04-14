# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: Thread Module
"""

#-- Import --#
import artParse as art
from utils import * 
#-- End Import --#

class android_threads():

	def getTLPointer(self, nPath, rAddr):
		k = open(nPath, 'rb')
		index = get_index('Runtime', 'thread_list_')
		k.seek(rAddr + index)
		TLPointer = hex(unpack_addr(k))
		k.close()
		return TLPointer

	#get list head, tail and size	
	def getTData(self, tAddr, path, memList):
		[start, key] = art.findAddr(tAddr, memList)
		listOff= int(tAddr, 16) -  int(start, 16)
		tPath = path+"/"+key
		index = get_index('ThreadList', 'list_')
		listAddr = hex(int(tAddr, 16) +index)	
		with open(tPath, 'rb') as g:
			g.seek(listOff + index)
			tl_head = hex(unpack_addr(g))
			tl_tail = hex(unpack_addr(g))
			tl_size = unpack_int(g)
			g.close()
		return [listAddr, tl_head,tl_tail,tl_size]	


	def procThread(self,listAddr, memList):
		[npath, offset] = art.getOffset(listAddr, memList)
		with open(npath, 'rb') as g:
			g.seek(offset)
			p1 = hex(unpack_addr(g))
			p2 = hex(unpack_addr(g))
			p3 = hex(unpack_addr(g))
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
		tls32_index = get_index('Thread','tls32_')
		thread_id_index = get_index('tls_32bit_sized_values', 'tid')
		tlsPtr_index = get_index('Thread','tlsPtr_')
		name_index = get_index('tls_ptr_sized_values', 'name')
		s_index = get_index('tls_ptr_sized_values', 'opeer')

		for t in tList:
			[tpath, offset] = art.getOffset(t, memList)	
			with open(tpath, 'rb') as g:
				g.seek(offset + tls32_index + thread_id_index)
				tid = unpack_uint(g)
				g.seek(offset + tlsPtr_index + name_index)
				strPointer = hex(unpack_addr(g))
				g.seek(offset + tlsPtr_index + s_index)
				tInstance = hex(unpack_addr(g))
				if VERSION == '8.0' and ARCH == 64:
					dPointer = 'To Fix'
				else:
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
			t = get_index('Monitor', 'owner')
			print t
			tList.append(t)
			threads = self.getThreads(tList, memList)
			mPath.close()
			return threads
		
		
		
		
		