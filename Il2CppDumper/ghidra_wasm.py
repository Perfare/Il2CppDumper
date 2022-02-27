# -*- coding: utf-8 -*-
import json

from wasm import WasmLoader
from wasm.analysis import WasmAnalysis
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
WasmLoader.loadElementsToTable(currentProgram, WasmAnalysis.getState(currentProgram).module, 0, 0, 0, monitor)

runScript("analyze_dyncalls.py")

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
progspace = currentProgram.addressFactory.getAddressSpace("ram")
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return progspace.getAddress(addr)

def set_name(addr, name):
	name = name.replace(' ', '-')
	createLabel(addr, name, True, USER_DEFINED)

def make_function(start):
	func = getFunctionAt(start)
	if func is None:
		createFunction(start, None)

f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))


if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	dynCallNamespace =  currentProgram.symbolTable.getNamespace("dynCall", None)
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		offset = scriptMethod["Address"]
		sig = scriptMethod["TypeSignature"]
		symbolName = "func_%s_%d" % (sig, offset)
		symbol = currentProgram.symbolTable.getSymbols(symbolName, dynCallNamespace)
		if len(symbol) > 0:
			addr = symbol[0].address
			name = scriptMethod["Name"].encode("utf-8")
			set_name(addr, name)
		else:
			print "Warning at %s:" % scriptMethod["Name"]
			print "Symbol %s not found!" % symbolName
		monitor.incrementProgress(1)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	monitor.initialize(len(scriptStrings))
	monitor.setMessage("Strings")
	for scriptString in scriptStrings:
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"].encode("utf-8")
		name = "StringLiteral_" + str(index)
		createLabel(addr, name, True, USER_DEFINED)
		setEOLComment(addr, value)
		index += 1
		monitor.incrementProgress(1)

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	monitor.initialize(len(scriptMetadatas))
	monitor.setMessage("Metadata")
	for scriptMetadata in scriptMetadatas:
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"].encode("utf-8")
		set_name(addr, name)
		setEOLComment(addr, name)
		monitor.incrementProgress(1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	monitor.initialize(len(scriptMetadataMethods))
	monitor.setMessage("Metadata Methods")
	for scriptMetadataMethod in scriptMetadataMethods:
		addr = get_addr(scriptMetadataMethod["Address"])
		name = scriptMetadataMethod["Name"].encode("utf-8")
		methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
		set_name(addr, name)
		setEOLComment(addr, name)
		monitor.incrementProgress(1)

if "Addresses" in data and "Addresses" in processFields:
	pass

print 'Script finished!'
