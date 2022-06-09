from binaryninja import *
from os.path import exists

def get_addr(bv: BinaryView, addr: int):
    imageBase = bv.start
    return imageBase + addr

class Il2CppProcessTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, script_path: str,
                 header_path: str):
        BackgroundTaskThread.__init__(self, "Il2Cpp start", True)
        self.bv = bv
        self.script_path = script_path
        self.header_path = header_path
        self.has_types = False
    
    def process_header(self):
        self.progress = "Il2Cpp types (1/3)"
        with open(self.header_path) as f:
            result = self.bv.parse_types_from_string(f.read())
        length = len(result.types)
        i = 0
        for name in result.types:
            i += 1
            if i % 100 == 0:
                percent = i / length * 100
                self.progress = f"Il2Cpp types: {percent:.2f}%"
            if self.bv.get_type_by_name(name):
                continue
            self.bv.define_user_type(name, result.types[name])
    
    def process_methods(self, data: dict):
        self.progress = f"Il2Cpp methods (2/3)"
        scriptMethods = data["ScriptMethod"]
        length = len(scriptMethods)
        i = 0
        for scriptMethod in scriptMethods:
            if self.cancelled:
                self.progress = "Il2Cpp cancelled, aborting"
                return
            i += 1
            if i % 100 == 0:
                percent = i / length * 100
                self.progress = f"Il2Cpp methods: {percent:.2f}%"
            addr = get_addr(self.bv, scriptMethod["Address"])
            name = scriptMethod["Name"].replace("$", "_").replace(".", "_")
            signature = scriptMethod["Signature"]
            func = self.bv.get_function_at(addr)
            if func != None:
                if func.name == name:
                    continue
                if self.has_types:
                    func.function_type = signature
                else:
                    func.name = scriptMethod["Name"]
        
    def process_strings(self, data: dict):
        self.progress = "Il2Cpp strings (3/3)"
        scriptStrings = data["ScriptString"]
        i = 0
        for scriptString in scriptStrings:
            i += 1
            if self.cancelled:
                self.progress = "Il2Cpp cancelled, aborting"
                return
            addr = get_addr(self.bv, scriptString["Address"])
            value = scriptString["Value"]
            var = self.bv.get_data_var_at(addr)
            if var != None:
                var.name = f"StringLiteral_{i}"
            self.bv.set_comment_at(addr, value)
    
    def run(self):
        if exists(self.header_path):
            self.process_header()
        else:
            log_warn("Header file not found")
        if self.bv.get_type_by_name("Il2CppClass"):
            self.has_types = True
        data = json.loads(open(self.script_path, 'rb').read().decode('utf-8'))
        if "ScriptMethod" in data:
            self.process_methods(data)
        if "ScriptString" in data:
            self.process_strings(data)

def process(bv: BinaryView):
    scriptDialog = OpenFileNameField("Select script.json", "script.json", "script.json")
    headerDialog = OpenFileNameField("Select il2cpp_binja.h", "il2cpp_binja.h", "il2cpp_binja.h")
    if not get_form_input([scriptDialog, headerDialog], "script.json from Il2CppDumper"):
        return log_error("File not selected, try again!")
    if not exists(scriptDialog.result):
        return log_error("File not found, try again!")
    task = Il2CppProcessTask(bv, scriptDialog.result, headerDialog.result)
    task.start()

PluginCommand.register("Il2CppDumper", "Process file", process)
