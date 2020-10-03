# -*- coding: utf-8 -*-
import json

from ghidra.app.util.cparser.C import CParserUtils
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
	name = name.replace(' ', '-')
	createLabel(addr, name, True, USER_DEFINED)

def set_type(addr, type):
	# Requires types (il2cpp.h) to be imported first
	newType = type.replace("*"," *").replace("  "," ").strip()
	dataTypes = getDataTypes(newType)
	if len(dataTypes) == 0:
		print("Could not identify type " + type + "(parsed as '" + newType + "')")
	elif len(dataTypes) > 1:
		print("Conflicting data types found for type " + type + "(parsed as '" + newType + "')")
	else:
		createData(addr, dataTypes[0])

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

def set_sig(addr, name, sig):
	# Should we include the type creation and/or import of header here rather
	# than to be performed separately? Like ida_with_struct script?
	# see also warnings in main ghidra console window
	try: 
		typeSig = CParserUtils.parseSignature(None, currentProgram, sig, False)
	except ghidra.app.util.cparser.C.ParseException:
		# sig wasn't able to be parsed; it could be a parameter name
		# that's reserved, an unidentified type, or something else
		print("Warning: Unable to parse")
		print(sig)
		print("Attempting to modify...")
		# try to fix by renaming the parameters
		try:
			newSig = sig.replace(", ","ext, ").replace("\)","ext\)")
			typeSig = CParserUtils.parseSignature(None, currentProgram, newSig, False)
		except:
			print("Warning: also unable to parse")
			print(newSig)
			print("Skipping.")
			return
	if typeSig is not None:
		typeSig.setName(name)
		ApplyFunctionSignatureCmd(addr, typeSig, USER_DEFINED, False, True).applyTo(currentProgram)

f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))

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
		createLabel(addr, name, True, USER_DEFINED)
		setEOLComment(addr, value)
		index += 1

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	for scriptMetadata in scriptMetadatas:
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"].encode("utf-8")
		set_name(addr, name)
		setEOLComment(addr, name)
		if scriptMetadata["Signature"]:
			set_type(addr, scriptMetadata["Signature"].encode("utf-8"))

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	for scriptMetadataMethod in scriptMetadataMethods:
		addr = get_addr(scriptMetadataMethod["Address"])
		name = scriptMetadataMethod["Name"].encode("utf-8")
		methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
		set_name(addr, name)
		setEOLComment(addr, name)

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
		sig = scriptMethod["Signature"][:-1].encode("utf-8")
		name = scriptMethod["Name"].encode("utf-8")
		set_sig(addr, name, sig)

print 'Script finished!'

