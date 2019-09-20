def getMethods(methods_):
	methods= OrderedDict()
	[g, objOff] = fromPointer(methods_, mapList)
	g.seek(objOff)
	size = struct.unpack("<i", g.read(4))[0]
	counter=1;
	while counter<=size:
		declaring_class_ = hex(struct.unpack("<I", g.read(4))[0])
		access_flags_ = struct.unpack("<i", g.read(4))[0]
		dex_code_item_offset_ = struct.unpack("<i", g.read(4))[0]
		dex_method_index_ =struct.unpack("<i", g.read(4))[0]
		method_index_=struct.unpack("<i", g.read(4))[0]
		methods[counter] = [declaring_class_,access_flags_,dex_code_item_offset_,dex_method_index_,method_index_]
		g.seek(g.tell()+12)
		counter+=1
	return methods