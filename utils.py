# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: DroidScraper configuration and useful unpack wrappers
"""

#-- Config parameters --#
VERSION = '8.0' # 8.0, 8.1 or 9
ARCH = 32 # 32 or 64
#--End Config parameters --#

#-- Import --#
import os
import subprocess
import struct
from collections import OrderedDict
#-- End Import --#

#-- Unpacking methods --#
unpack_uint = lambda fhandle: struct.unpack('<I', fhandle.read(4))[0]
unpack_int = lambda fhandle: struct.unpack('<i', fhandle.read(4))[0]
unpack_b = lambda fhandle: struct.unpack('<B', fhandle.read(1))[0] #Byte or Bool
unpack_bool = lambda fhandle: struct.unpack('<?', fhandle.read(1))[0]
unpack_char = lambda fhandle: struct.unpack('<c', fhandle.read(1))[0]
unpack_ushort = lambda fhandle: struct.unpack('<H', fhandle.read(2))[0]
unpack_float = lambda fhandle: struct.unpack('<f', fhandle.read(4))[0]
unpack_ulong = lambda fhandle: struct.unpack('<Q', fhandle.read(8))[0]
unpack_double = lambda fhandle: struct.unpack('<d', fhandle.read(8))[0]

unpack_addr = lambda fhandle: unpack_uint(fhandle) if ARCH==32 else unpack_ulong(fhandle)
#-- End Unpacking methods --#

#-- Offsets import --#
if ARCH == 32:
	if VERSION == '8.0':
		from artTypes_8_0_32 import types
	elif VERSION == '8.1':
		from artTypes_8_1_32 import types
	elif VERSION == '9':
		from artTypes_9_32 import types
	else:
		raise ImportError('Offsets cannot be imported. Supported versions are: 8.0, 8.1 and 9')
elif ARCH == 64:
	if VERSION == '8.0':
		from artTypes_8_0_64 import types
	elif VERSION == '8.1':
		from artTypes_8_1_64 import types
	elif VERSION == '9':
		from artTypes_9_64 import types
	else:
		raise ImportError('Offsets cannot be imported. Supported versions are: 8.0, 8.1 and 9')
else:
	raise ImportError('Offsets cannot be imported. Supported architectures are: 32 and 64')

get_index = lambda class_name, attribute_name: types.get(class_name)[1].get(attribute_name)[0]
get_class_size = lambda class_name: types.get(class_name)[0]
#-- End Offsets import --#