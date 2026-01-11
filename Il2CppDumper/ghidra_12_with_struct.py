# -*- coding: utf-8 -*-
import json

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.app.util.cparser.C import CParserUtils, ParseException
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, FunctionRenameOption
from ghidra.program.model.data import DataTypeConflictHandler

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
	try:
		name = name.replace(' ', '-')
		createLabel(addr, name, True, SourceType.USER_DEFINED)
	except Exception as e:
		print("set_name() Failed: " + str(e))

def set_type(addr, type):
	# Requires types (il2cpp.h) to be imported first
	newType = type.replace("*"," *").replace("  "," ").strip()
	dataTypes = getDataTypes(newType)
	addrType = None
	if len(dataTypes) == 0:
		if newType.endswith(" *"):
			baseType = newType[:-2]
			dataTypes = getDataTypes(baseType)
			if len(dataTypes) == 1:
				dtm = currentProgram.getDataTypeManager()
				pointerType = dtm.getPointer(dataTypes[0])
				addrType = dtm.addDataType(pointerType, None)
	elif len(dataTypes) > 1:
		print("Conflicting data types found for type " + type + "(parsed as '" + newType + "')")
		return
	else:
		addrType = dataTypes[0]
	if addrType is None:
		print("Could not identify type " + type + "(parsed as '" + newType + "')")
	else:
		try:
			createData(addr, addrType)
		except CodeUnitInsertionException as e:
			print("Warning: unable to set type: " + str(e))

def make_function(start):
	func = getFunctionAt(start)
	if func is None:
		try:
			createFunction(start, None)
		except:
			print("Warning: Unable to create function")

def set_sig(addr, name, sig):
	try:
		typeSig = CParserUtils.parseSignature(None, currentProgram, sig, False)
	except ParseException:
		print('Warning: Unable to parse "' + sig + '", attempting to modify...')
		# try to fix by renaming the parameters
		newSig = sig.replace(", ","ext, ").replace(")","ext)")
		try:
			typeSig = CParserUtils.parseSignature(None, currentProgram, newSig, False)
		except ParseException as e:
			print('Warning: also unable to parse "' + newSig + '", skipping: ' + str(e))
			return
		print('Successfully modified and parsed the signature as "' + newSig + '"')
	if typeSig is not None:
		try:
			typeSig.setName(name)
			cmd = ApplyFunctionSignatureCmd(addr, typeSig, SourceType.USER_DEFINED, False, False, DataTypeConflictHandler.
REPLACE_HANDLER, FunctionRenameOption.RENAME)
			cmd.applyTo(currentProgram)
		except Exception as e:
			print("Warning: unable to set Signature. ApplyFunctionSignatureCmd() Failed: " + str(e))

f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'r', encoding='utf-8').read())

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"]
		set_name(addr, name)
		monitor.incrementProgress(1)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	monitor.initialize(len(scriptStrings))
	monitor.setMessage("Strings")
	for scriptString in scriptStrings:
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"]
		name = "StringLiteral_" + str(index)
		createLabel(addr, name, True, SourceType.USER_DEFINED)
		setEOLComment(addr, value)
		index += 1
		monitor.incrementProgress(1)

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	monitor.initialize(len(scriptMetadatas))
	monitor.setMessage("Metadata")
	for scriptMetadata in scriptMetadatas:
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"]
		set_name(addr, name)
		setEOLComment(addr, name)
		if scriptMetadata["Signature"]:
			set_type(addr, scriptMetadata["Signature"])
		monitor.incrementProgress(1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	monitor.initialize(len(scriptMetadataMethods))
	monitor.setMessage("Metadata Methods")
	for scriptMetadataMethod in scriptMetadataMethods:
		addr = get_addr(scriptMetadataMethod["Address"])
		name = scriptMetadataMethod["Name"]
		methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
		set_name(addr, name)
		setEOLComment(addr, name)
		monitor.incrementProgress(1)

if "Addresses" in data and "Addresses" in processFields:
	addresses = data["Addresses"]
	monitor.initialize(len(addresses))
	monitor.setMessage("Addresses")
	for address in addresses:
		start = get_addr(address)
		make_function(start)
		monitor.incrementProgress(1)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Signatures")
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		sig = scriptMethod["Signature"][:-1]
		name = scriptMethod["Name"]
		set_sig(addr, name, sig)
		monitor.incrementProgress(1)

print('Script finished!')
