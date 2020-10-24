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
	ret = idc.MakeNameEx(addr, name, SN_NOWARN | SN_NOCHECK)
	if ret == 0:
		new_name = name + '_' + str(addr)
		ret = idc.MakeNameEx(addr, new_name, SN_NOWARN | SN_NOCHECK)

def make_function(start, end):
	next_func = idc.NextFunction(start)
	if next_func < end:
		end = next_func
	if idc.GetFunctionAttr(start, FUNCATTR_START) == start:
		idc.DelFunction(start)
	idc.MakeFunction(start, end)

path = idaapi.askfile_c(False, '*.json', 'script.json from Il2cppdumper')
data = json.loads(open(path, 'rb').read().decode('utf-8'))

if "Addresses" in data and "Addresses" in processFields:
	addresses = data["Addresses"]
	for index in range(len(addresses) - 1):
		start = get_addr(addresses[index])
		end = get_addr(addresses[index + 1])
		make_function(start, end)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"].encode("utf-8")
		set_name(addr, name)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	for scriptString in scriptStrings:
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"].encode("utf-8")
		name = "StringLiteral_" + str(index)
		idc.MakeNameEx(addr, name, SN_NOWARN)
		idc.MakeRptCmt(addr, value)
		index += 1

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	for scriptMetadata in scriptMetadatas:
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"].encode("utf-8")
		set_name(addr, name)
		idc.MakeRptCmt(addr, name)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	for scriptMetadataMethod in scriptMetadataMethods:
		addr = get_addr(scriptMetadataMethod["Address"])
		name = scriptMetadataMethod["Name"].encode("utf-8")
		methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
		set_name(addr, name)
		idc.MakeRptCmt(addr, name)
		idc.MakeComm(addr, '{0:X}'.format(methodAddr))

print 'Script finished!'

