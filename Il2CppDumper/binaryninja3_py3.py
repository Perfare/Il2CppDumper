import binaryninja
from os.path import exists

imageBase = bv.start

def get_addr(addr):
	return imageBase + addr

fileDialog = OpenFileNameField("Select script.json", "script.json", "script.json")

if get_form_input([fileDialog], "script.json from Il2CppDumper") != 1:
    print("File not selected, try again!")
else:
    if exists(fileDialog.result) == True:
        data = json.loads(open(fileDialog.result, 'rb').read().decode('utf-8'))
        data["Addresses"] = None
        if "ScriptMethod" in data:
            scriptMethods = data["ScriptMethod"]
            for scriptMethod in scriptMethods:
                addr = get_addr(scriptMethod["Address"])
                name = scriptMethod["Name"]
                func = bv.get_function_at(addr)
                if func != None:
                    bv.get_function_at(addr).name = name
            print("Done")
    else:
        print("File not found")