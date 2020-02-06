# -*- coding: utf-8 -*-
import ghidra.program.model.symbol.SourceType
import re

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED
index = 1

def _convert_arg_addr(arg):
    return baseAddress.add(int(arg, 0))

def _convert_arg_string(arg):
    if arg.startswith('r'):
        return arg[2:-1]
    return arg[1:-1]

def do_idc_set_cmt(arg1, arg2):
    addr = _convert_arg_addr(arg1)
    text = _convert_arg_string(arg2)
    setEOLComment(addr, text)

def do_SetName(arg1, arg2):
    addr = _convert_arg_addr(arg1)
    name = _convert_arg_string(arg2)
    createLabel(addr, name, True, USER_DEFINED)

def do_SetString(arg1, arg2):
    addr = _convert_arg_addr(arg1)
    text = _convert_arg_string(arg2)
    
    global index
    name = "StringLiteral_" + str(index);
    createLabel(addr, name, True, USER_DEFINED)
    setEOLComment(addr, text)
    index += 1

def do_MakeFunction(arg1, arg2):
    start = _convert_arg_addr(arg1)
    end = _convert_arg_addr(arg2)
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

f = askFile("ida.py from Il2cppdumper", "Open")
for line in file(f.absolutePath):
    match = re.search(r"^([\w+\.]+)\((\w+),\s*(.*)\)$", line)
    if match:
        name, arg1, arg2 = match.groups()
        res = globals()['do_'+name.replace('.', '_')](arg1, arg2.replace(' ', '-'))