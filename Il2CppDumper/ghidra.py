# -*- coding: utf-8 -*-
import json

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
	name = name.replace(' ', '-')
	createLabel(addr, name, True, USER_DEFINED)

def make_function(start, end):
	next_func_start = getFunctionAfter(start).getEntryPoint()
	if next_func_start < end:
		end = next_func_start
	body = createAddressSet()
	body.addRange(start, end.subtract(1))
	functionManager.deleteAddressRange(start, end.subtract(1), getMonitor())
	func = getFunctionAt(start)
	if func is None:
		functionManager.createFunction(None, start, body, USER_DEFINED)
	else:
		func.setBody(body)

print 'Script: Edit config.json and set MakeFunction to false to speed up ghidra script execution'
f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))
scriptMethods = data["ScriptMethod"]
for scriptMethod in scriptMethods:
	addr = get_addr(scriptMethod["Address"])
	name = scriptMethod["Name"].encode("utf-8")
	set_name(addr, name)
index = 1
scriptStrings = data["ScriptString"]
for scriptString in scriptStrings:
	addr = get_addr(scriptString["Address"])
	value = scriptString["Value"].encode("utf-8")
	name = "StringLiteral_" + str(index)
	createLabel(addr, name, True, USER_DEFINED)
	setEOLComment(addr, value)
	index += 1
scriptMetadatas = data["ScriptMetadata"]
for scriptMetadata in scriptMetadatas:
	addr = get_addr(scriptMetadata["Address"])
	name = scriptMetadata["Name"].encode("utf-8")
	set_name(addr, name)
	setEOLComment(addr, name)
scriptMetadataMethods = data["ScriptMetadataMethod"]
for scriptMetadataMethod in scriptMetadataMethods:
	addr = get_addr(scriptMetadataMethod["Address"])
	name = scriptMetadataMethod["Name"].encode("utf-8")
	methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
	set_name(addr, name)
	setEOLComment(addr, name)
addresses = data["Addresses"]
for index in range(len(addresses) - 1):
	start = get_addr(addresses[index])
	end = get_addr(addresses[index + 1])
	make_function(start, end)
print 'Script finished!'