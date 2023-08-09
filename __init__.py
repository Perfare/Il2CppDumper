from binaryninja import *
from os.path import exists
from .ilp import *


script_data = None


def get_addr(bv: BinaryView, relative_addr: int):
    base_addr = bv.start
    return base_addr + relative_addr


class IL2CPPProcessTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, script_path: str, header_path: str):
        BackgroundTaskThread.__init__(self, "IL2CPP Initialise", True)
        self.bv = bv
        self.script_path = script_path
        self.header_path = header_path

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
                if f == None:
                    f = self.bv.create_user_function(addr)
                if f != None:
                    if f.name == name:
                        continue
                    else:
                        f.name = name
                    # Setting the type directly via
                    # f.type = sig
                    # is too slow for analysis.
            except Exception:
                log_info(f"Unable to add method {name}")

    def process_strings(self, data: dict):
        self.progress = "Adding IL2CPP Strings"
        stringList = data["ScriptString"]

        N = len(stringList)
        i = 0
        for string in stringList:
            if self.cancelled:
                self.progress = "IL2CPP cancelled. Aborting..."
                return

            i += 1
            if i % 100 == 0:
                percentage = 100*i / N
                self.progress = f"IL2CPP ScriptString: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, string["Address"])
            value = string["Value"]
            var = self.bv.get_data_var_at(addr)
            try:

                if var != None:
                    var.name = f"StringLiteral_{i}"
                else:
                    self.bv.define_user_data_var(
                        addr, "void*", f"StringLiteral_{i}")
                self.bv.set_comment_at(addr, value)
            except Exception:
                log_info(f"Unable to add string at {addr}")

    def process_data(self, data: dict):
        self.progress = "Adding IL2CPP ScriptMetadata"
        metadataList = data["ScriptMetadata"]

        i = 0
        N = len(metadataList)
        for metadata in metadataList:
            if self.cancelled:
                self.progress = "IL2CPP cancelled. Aborting..."
                return

            i += 1
            if i % 100 == 0:
                percentage = 100*i / N
                self.progress = f"IL2CPP ScriptMetadata: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, metadata["Address"])
            sign = metadata["Signature"]
            name = metadata["Name"]
            var = self.bv.get_data_var_at(addr)
            try:

                if var != None:
                    var.name = name
                else:
                    self.bv.define_user_data_var(addr, "void*", name)
                self.bv.set_comment_at(addr, sign)
            except Exception as e:
                log_info(f"Unable to add metadata at {addr} {str(e)}")

    def process_method_data(self, data: dict):
        self.progress = "Adding IL2CPP ScriptMetadataMethod"
        metadataList = data["ScriptMetadataMethod"]

        i = 0
        N = len(metadataList)
        for metadata in metadataList:
            if self.cancelled:
                self.progress = "IL2CPP cancelled. Aborting..."
                return

            i += 1
            if i % 100 == 0:
                percentage = 100*i / N
                self.progress = f"IL2CPP ScriptMetadataMethod: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, metadata["Address"])
            method_addr = metadata["MethodAddress"]
            name = metadata["Name"]
            var = self.bv.get_data_var_at(addr)
            try:
                if var != None:
                    var.name = name
                else:
                    self.bv.define_user_data_var(addr, "void*", name)
                self.bv.set_comment_at(addr, str(method_addr))
            except Exception as e:
                log_info(f"Unable to add metadata at {addr} {str(e)}")

    def run(self):
        data = json.loads(open(self.script_path, 'rb').read().decode('utf-8'))
        global script_data
        script_data = data
        if "ScriptMethod" in data:
            self.process_methods(data)
        if "ScriptString" in data:
            self.process_strings(data)
        if "ScriptMetadata" in data:
            self.process_data(data)
        if "ScriptMetadataMethod" in data:
            self.process_method_data(data)
        self.progress = "Loading il2cpp.h"
        load_file(self.header_path)
        log_info("IL2CPPDumper data loaded")


def process(bv: BinaryView):
    scriptDialog = OpenFileNameField(
        "Select script.json", "script.json", "script.json")
    headerDialog = OpenFileNameField(
        "Select il2cpp.h", "il2cpp.h", "il2cpp.h")
    if not get_form_input([scriptDialog, headerDialog], "Select IL2CPPDumper outputs"):
        return log_error("File not selected.")
    if not exists(scriptDialog.result):
        return log_error("File not found.")
    if not exists(headerDialog.result):
        return log_error("File not found.")
    task = IL2CPPProcessTask(bv, scriptDialog.result, headerDialog.result)
    task.start()


def annotate(bv: BinaryView, addr: int):
    laddr = addr - bv.start

    method = first_or_else(
        [m for m in script_data["ScriptMethod"] if m["Address"] == laddr], None)
    log_info(method)
    if method is not None:
        address = method["Address"]
        name = method["Name"]
        signature = method["Signature"]
        refs = find_refs(parser.parse(str.encode(signature)).root_node)
        header = "#include <stdint.h>\n"
        mark = set()
        for ref in refs:
            header += build_struct(ref.decode("utf-8"), mark)
        header += signature
        log_debug("header = \n", header)
        tys = bv.parse_types_from_string(header)
        for t_name in tys.types:
            if not bv.get_type_by_name(t_name):
                bv.define_user_type(t_name, tys.types[t_name])
        ty_f = first_or_else(list(tys.functions.values()), None)
        if ty_f is not None:
            fn = bv.get_function_at(addr)
            if fn is None:
                fn = bv.add_function(addr)
            fn.name = name
            fn.type = ty_f
            fn.request_advanced_analysis_data()
            log_info(f"defined func at {addr}")

    metadata = first_or_else(
        [m for m in script_data["ScriptMetadata"] if m["Address"] == laddr], None)
    if metadata is not None:
        address = metadata["Address"]
        name = metadata["Name"]
        signature: str = metadata["Signature"]
        ref = signature[:signature.find("*")]
        header = "#include <stdint.h>\n" + build_struct(ref, set())
        log_debug("header = \n", header)
        tys = bv.parse_types_from_string(header)
        for t_name in tys.types:
            if not bv.get_type_by_name(t_name):
                bv.define_user_type(t_name, tys.types[t_name])
        var = bv.get_data_var_at(addr)
        if var is None:
            bv.define_user_data_var(addr, signature, name)
        else:
            var.name = name
            var.type = signature
        log_info(f"defined var at {addr}")

    if method is None and metadata is None:
        log_info("No metadata found.")


def annotate_valid(bv: BinaryView, addr: int):
    return script_data is not None and len(ilp.typedefs) > 0


def register():
    PluginCommand.register("IL2CPPDumper Load", "Process File", process)
    PluginCommand.register_for_address(
        "IL2CPPDumper Annotate", "Process File", annotate, annotate_valid)


register()
