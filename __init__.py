from binaryninja import *
from os.path import exists

def get_addr(bv: BinaryView, relative_addr: int):
    base_addr = bv.start
    return base_addr + relative_addr

class IL2CPPProcessTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, script_path: str):
        BackgroundTaskThread.__init__(self, "IL2CPP Initialise", True)
        self.bv = bv
        self.script_path = script_path

    def process_methods(self, data: dict):
        self.progress = "Adding IL2CPP Methods"
        methodList = data["ScriptMethod"]
        
        N = len(methodList)
        i = 0

        for method in methodList:
            if self.cancelled:
                self.progress = f"IL2CPP cancelled. Aborting..."
                return
            
            i += 1
            if i % 100 == 0:
                percentage = 100*i / N
                self.progress = f"IL2CPP Methods: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, method["Address"])
            name = method["Name"].replace("$", "_").replace(".", "_")
            sig = method["Signature"]
            f = self.bv.get_function_at(addr)

            try:
                if f != None:
                    if f.name == name:
                        continue
                    else:
                        f.name = name
                    # Setting the type directly via
                    # f.type = sig
                    # is too slow for analysis.
                    f.add_tag("Signature", sig)
            except Exception:
                log_info(f"Unable to add method {name}")

    def process_strings(self, data: dict):
        self.progress = "Adding IL2CPP Strings"
        stringList = data["ScriptString"]

        i = 0
        for string in stringList:
            if self.cancelled:
                self.progress = "IL2CPP cancelled. Aborting..."
                return

            addr = get_addr(self.bv, string["Address"])
            value = string["Value"]
            var = self.bv.get_data_var_at(addr)
            try:
                if var != None:
                    var.name = f"StringLiteral_{i}"
                    i += 1
                self.bv.set_comment_at(addr, value)
            except Exception:
                log_info(f"Unable to add string at {addr}")

    def run(self):
        data = json.loads(open(self.script_path, 'rb').read().decode('utf-8'))
        self.bv.create_tag_type("Signature", "📜")
        if "ScriptMethod" in data:
            self.process_methods(data)
        if "ScriptString" in data:
            self.process_strings(data)

def process(bv: BinaryView):
    scriptDialog = OpenFileNameField("Select script.json", "script.json", "script.json")
    if not get_form_input([scriptDialog], "script.json"):
        return log_error("File not selected.")
    if not exists(scriptDialog.result):
        return log_error("File not found.")
    task = IL2CPPProcessTask(bv, scriptDialog.result)
    task.start()

PluginCommand.register("IL2CPPDumper", "Process File", process)
