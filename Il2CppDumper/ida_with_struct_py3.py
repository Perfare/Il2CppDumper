# -*- coding: utf-8 -*-
import json
import idaapi
import idc
import ida_funcs
import ida_bytes
import ida_segment
import ida_typeinf
import ida_dirtree
import ida_xref
import ida_auto
import ida_ida

PROCESS_FIELDS = {
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
    "TypeInfoPointers",
    "TypeRefPointers",
    "FieldInfos",
}

IMAGE_BASE = idaapi.get_imagebase()
if IMAGE_BASE == 0:
    IMAGE_BASE = 0x7100000000  # NSO default load address (Nintendo Switch)
IS_64BIT   = ida_ida.inf_is_64bit()
PATCH_WORD = ida_bytes.patch_qword if IS_64BIT else ida_bytes.patch_dword
WORD_FLAG  = idc.FF_QWORD if IS_64BIT else idc.FF_DWORD

_STR_TI = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(_STR_TI, None, "const char* const;", 0)

_SIG_CACHE = {}

def get_addr(addr):
    return IMAGE_BASE + addr

def set_name(addr, name):
    if idc.set_name(addr, name, idc.SN_NOWARN | idc.SN_NOCHECK) == 0:
        idc.set_name(addr, name + '_' + str(addr), idc.SN_NOWARN | idc.SN_NOCHECK)

def make_function(start, end):
    nf = idc.get_next_func(start)
    if nf < end:
        end = nf
    if idc.get_func_attr(start, idc.FUNCATTR_START) == start:
        ida_funcs.del_func(start)
    ida_funcs.add_func(start, end)

def apply_sig(addr, sig):
    if sig not in _SIG_CACHE:
        pt = ida_typeinf.tinfo_t()
        _SIG_CACHE[sig] = pt if ida_typeinf.parse_decl(pt, None, sig, 0) else None
    ti = _SIG_CACHE[sig]
    if ti:
        ida_typeinf.apply_tinfo(addr, ti, ida_typeinf.TINFO_DEFINITE)

def add_cross_reference(from_addr, to_addr):
    ida_xref.add_dref(from_addr, to_addr, ida_xref.XREF_USER | ida_xref.dr_I)

ida_auto.set_ida_state(ida_auto.st_Work)
idc.set_inf_attr(idc.INF_SHORT_DEMNAMES, idc.DEMNAM_GCC3)

path  = idaapi.ask_file(False, '*.json', 'script.json from Il2cppdumper')
hpath = idaapi.ask_file(False, '*.h', 'il2cpp.h from Il2cppdumper')

with open(hpath, 'r', encoding='utf-8') as f:
    ida_typeinf.parse_decls(None, f.read(), None, 0)

with open(path, 'rb') as f:
    data = json.loads(f.read().decode('utf-8'))

active = PROCESS_FIELDS & set(data.keys())

func_dirtree = None
try:
    func_dirtree = ida_dirtree.dirtree_t(ida_dirtree.DIRTREE_FUNCS)
except Exception:
    pass

if "Addresses" in active:
    idaapi.show_wait_box("Processing Addresses...")
    mapped = [get_addr(a) for a in data["Addresses"]]
    for i in range(len(mapped) - 1):
        make_function(mapped[i], mapped[i + 1])
    idaapi.hide_wait_box()

if "ScriptMethod" in active:
    idaapi.show_wait_box("Processing Methods...")
    for m in data["ScriptMethod"]:
        addr = get_addr(m["Address"])
        set_name(addr, m["Name"])

        group = m.get("Group")
        if func_dirtree and group:
            func_dirtree.mkdir(group)
            fn = ida_funcs.get_func_name(addr)
            func_dirtree.rename(fn, "{}/{}".format(group, fn))

        sig = m.get("Signature")
        if sig:
            apply_sig(addr, sig)
    idaapi.hide_wait_box()

if "ScriptString" in active:
    idaapi.show_wait_box("Processing Strings...")
    script_strings = data["ScriptString"]

    encoded = [s["Value"].encode('utf-8') for s in script_strings]
    total_len = sum(len(v) + 1 for v in encoded)

    fake_seg_start = (ida_ida.inf_get_max_ea() + 0xFFF) & ~0xFFF
    ida_segment.add_segm(0, fake_seg_start, fake_seg_start + total_len, ".fake_strings", "DATA")

    cur = fake_seg_start
    for s, value in zip(script_strings, encoded):
        addr = get_addr(s["Address"])
        ida_bytes.put_bytes(cur, value + b'\x00')
        PATCH_WORD(addr, cur)
        ida_typeinf.apply_tinfo(addr, _STR_TI, ida_typeinf.TINFO_DEFINITE)
        name = s.get("Name") or ("StringLiteral_" + str(s["Address"]))
        idc.set_name(addr, name, idc.SN_NOWARN | idc.SN_NOCHECK)
        cur += len(value) + 1
    idaapi.hide_wait_box()

if "ScriptMetadata" in active:
    idaapi.show_wait_box("Processing Metadata...")
    for m in data["ScriptMetadata"]:
        addr = get_addr(m["Address"])
        set_name(addr, m["Name"])
        idc.set_cmt(addr, m["Name"], 1)
        sig = m.get("Signature")
        if sig:
            apply_sig(addr, sig if sig.endswith(";") else sig + ";")
    idaapi.hide_wait_box()

if "ScriptMetadataMethod" in active:
    idaapi.show_wait_box("Processing MethodInfo Cross-References...")
    for m in data["ScriptMetadataMethod"]:
        addr        = get_addr(m["Address"])
        method_addr = get_addr(m["MethodAddress"])
        set_name(addr, m["Name"])
        if method_addr > IMAGE_BASE:
            add_cross_reference(method_addr, addr)
    idaapi.hide_wait_box()

if "TypeInfoPointers" in active:
    idaapi.show_wait_box("Processing TypeInfo Pointers...")
    for t in data["TypeInfoPointers"]:
        addr = get_addr(t["Address"])
        set_name(addr, t["Name"])
        type_str = t.get("Type")
        if type_str:
            apply_sig(addr, type_str if type_str.endswith(";") else type_str + ";")
    idaapi.hide_wait_box()

if "FieldInfos" in active:
    idaapi.show_wait_box("Processing Field Infos...")
    for f in data["FieldInfos"]:
        addr = get_addr(f["Address"])
        set_name(addr, f["Name"])
        idc.set_cmt(addr, f["Value"], 1)
    idaapi.hide_wait_box()

ida_auto.set_ida_state(ida_auto.st_Ready)
print('Il2CppDumper Script finished successfully!')
