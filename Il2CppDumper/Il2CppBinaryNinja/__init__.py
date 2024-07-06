from binaryninja import *
from os.path import exists
from .ilp import *


script_data = None


def get_addr(bv: BinaryView, relative_addr: int):
    base_addr = bv.start
    return base_addr + relative_addr


class IL2CPPProcessTask(BackgroundTaskThread):
    def __init__(
        self, bv: BinaryView, script_path: str, header_path: str, skip_naming: bool
    ):
        BackgroundTaskThread.__init__(self, "IL2CPP Initialise", True)
        self.bv = bv
        self.script_path = script_path
        self.header_path = header_path
        self.skip_naming = skip_naming

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
                percentage = 100 * i / N
                self.progress = f"IL2CPP Methods: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, method["Address"])
            name = method["Name"]
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
                percentage = 100 * i / N
                self.progress = f"IL2CPP ScriptString: {percentage:.2f}% ({i}/{N})"

            addr = get_addr(self.bv, string["Address"])
            value = string["Value"]
            var = self.bv.get_data_var_at(addr)
            try:
                if var != None:
                    var.name = f"StringLiteral_{i}"
                else:
                    self.bv.define_user_data_var(addr, "void*", f"StringLiteral_{i}")
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
                percentage = 100 * i / N
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
                percentage = 100 * i / N
                self.progress = (
                    f"IL2CPP ScriptMetadataMethod: {percentage:.2f}% ({i}/{N})"
                )

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
        data = json.loads(open(self.script_path, "rb").read().decode("utf-8"))
        global script_data
        script_data = data
        if not self.skip_naming:
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
    scriptDialog = OpenFileNameField("Select script.json", "script.json", "script.json")
    headerDialog = OpenFileNameField("Select il2cpp.h", "il2cpp.h", "il2cpp.h")
    skip_naming = ChoiceField("Skip naming", ["Yes", "No"])
    if not get_form_input(
        [scriptDialog, headerDialog, skip_naming], "Select IL2CPPDumper outputs"
    ):
        return log_error("File not selected.")
    if not exists(scriptDialog.result):
        return log_error("File not found.")
    if not exists(headerDialog.result):
        return log_error("File not found.")
    task = IL2CPPProcessTask(
        bv, scriptDialog.result, headerDialog.result, skip_naming.result == 0
    )
    task.start()


class IL2CPPAnnotateTask(BackgroundTaskThread):
    def __init__(self, addr: int, bv: BinaryView):
        super().__init__("annotating function", False)
        self.addr = addr
        self.bv = bv

    def load_types(self, header: str):
        log_debug(f"header = {header}\n")
        tys = self.bv.parse_types_from_string(header)
        for t_name in tys.types:
            if not self.bv.get_type_by_name(t_name):
                self.bv.define_user_type(t_name, tys.types[t_name])
        return tys

    def annotate_method(self, addr: int):
        laddr = addr - self.bv.start
        method = first_or_else(
            [m for m in script_data["ScriptMethod"] if m["Address"] == laddr], None
        )
        if method is None:
            return None

        address = method["Address"]
        name = method["Name"]
        signature = method["Signature"].replace("* method);", "* __method);")
        log_debug(f"signature = {signature}")

        refs = find_refs(parser.parse(str.encode(signature)).root_node)
        header = "#include <stdint.h>\n"
        mark = set()
        for ref in refs:
            header += build_struct(ref.decode("utf-8"), mark)
        header += signature
        tys = self.load_types(header)

        ty_f = first_or_else(list(tys.functions.values()), None)
        if ty_f is None:
            log_error(f"failed to parse function {signature}")
            return None

        fn = self.bv.get_function_at(addr)
        if fn is None:
            fn = self.bv.add_function(addr)
        fn.name = name
        fn.type = ty_f
        fn.request_advanced_analysis_data()
        log_info(f"defined func at {addr}")
        return fn

    def annotate_child(self, fn: Function):
        self.progress = f"Annotating child functions of {fn}"
        component = self.bv.create_component()
        component.add_function(fn)
        self.bv.update_analysis_and_wait()
        for ref_addr in component.get_referenced_data_variables():
            log_info(f"annotate child {ref_addr} of {fn}")
            method = self.annotate_method(ref_addr.address)
            if method is None:
                self.annotate_var(ref_addr.address)
        self.bv.remove_component(component)
        log_info(f"Annotating {fn} finished")
        return True

    def annotate_var(self, addr: int):
        laddr = addr - self.bv.start
        metadata = first_or_else(
            [m for m in script_data["ScriptMetadata"] if m["Address"] == laddr], None
        )
        if metadata is None:
            return None

        address = metadata["Address"]
        name = metadata["Name"]
        signature: str = metadata["Signature"]

        ref = signature[: signature.find("*")]
        header = "#include <stdint.h>\n" + build_struct(ref, set())
        _ = self.load_types(header)
        var = self.bv.get_data_var_at(addr)
        if var is None:
            var = self.bv.define_user_data_var(addr, signature, name)
        else:
            var.name = name
            var.type = signature
        log_info(f"defined var at {addr}")
        return var

    def run(self):
        method = self.annotate_method(self.addr)
        var = self.annotate_var(self.addr)
        if method is None:
            for fn in self.bv.get_functions_containing(self.addr):
                log_info(f"Annotating surrounding function {fn}")
                method = method or self.annotate_method(fn.start)
        if method is not None:
            self.annotate_child(method)
        if not method and not var:
            log_info(f"No metadata found for {self.addr}.")


def annotate(bv: BinaryView, addr: int):
    task = IL2CPPAnnotateTask(addr, bv)
    task.start()


def annotate_valid(bv: BinaryView, addr: int):
    return script_data is not None and len(ilp.typedefs) > 0


def register():
    PluginCommand.register("IL2CPPDumper Load", "Process File", process)
    PluginCommand.register_for_address(
        "IL2CPPDumper Annotate", "Process File", annotate, annotate_valid
    )


register()
