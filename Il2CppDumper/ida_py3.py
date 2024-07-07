# -*- coding: utf-8 -*-
import json

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

imageBase = idaapi.get_imagebase()

def get_addr(addr):
	return imageBase + addr

def set_name(addr, name):
	ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
	if ret == 0:
		new_name = name + '_' + str(addr)
		ret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)

def make_function(start, end):
	next_func = idc.get_next_func(start)
	if next_func < end:
		end = next_func
	if idc.get_func_attr(start, FUNCATTR_START) == start:
		ida_funcs.del_func(start)
	ida_funcs.add_func(start, end)

def show_progress(field, current, total):
    if current % 100 == 0:
        msg = f"Processing {field} {current}/{total} {current * 100 / total:.2f}%"
        idaapi.replace_wait_box(msg)

path = idaapi.ask_file(False, '*.json', 'script.json from Il2cppdumper')
data = json.loads(open(path, 'rb').read().decode('utf-8'))

if "Addresses" in data and "Addresses" in processFields:
	addresses = data["Addresses"]
	for index in range(len(addresses) - 1):
		show_progress("Addresses", index, len(addresses))
		start = get_addr(addresses[index])
		end = get_addr(addresses[index + 1])
		make_function(start, end)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	for (index, scriptMethod) in enumerate(scriptMethods):
		show_progress("ScriptMethod", index, len(scriptMethods))
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"]
		set_name(addr, name)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	for (index, scriptString) in enumerate(scriptStrings):
		show_progress("ScriptString", index, len(scriptStrings))
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"]
		name = "StringLiteral_" + str(index)
		idc.set_name(addr, name, SN_NOWARN)
		idc.set_cmt(addr, value, 1)
		index += 1

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	for (index, scriptMetadata) in enumerate(scriptMetadatas):
		show_progress("ScriptMetadata", index, len(scriptMetadatas))
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"]
		set_name(addr, name)
		idc.set_cmt(addr, name, 1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	for (index, scriptMetadataMethod) in enumerate(scriptMetadataMethods):
		show_progress("ScriptMetadataMethod", index, len(scriptMetadataMethods))
		addr = get_addr(scriptMetadataMethod["Address"])
		name = scriptMetadataMethod["Name"]
		methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
		set_name(addr, name)
		idc.set_cmt(addr, name, 1)
		idc.set_cmt(addr, '{0:X}'.format(methodAddr), 0)

print('Script finished!')

