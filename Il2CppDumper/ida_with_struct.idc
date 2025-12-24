#include <idc.idc>

static readint32(file)
{
    auto num;
    file.readbytes(&num, 4, 0);
    return num;
}

static readint64(file)
{
    auto num;
    file.readbytes(&num, 8, 0);
    return num;
}

static readstring(file)
{
    auto str, len;
    len = readint32(file);
    file.read(&str, len);
    return str;
}

static ReadScriptMethod(file)
{
    auto o = object();
    o.Address = readint64(file);
    o.Name = readstring(file);
    o.Signature = readstring(file);
    o.TypeSignature = readstring(file);
    return o;
}

static ReadScriptString(file)
{
    auto o = object();
    o.Address = readint64(file);
    o.Value = readstring(file);
    return o;
}

static ReadScriptMetadata(file)
{
    auto o = object();
    o.Address = readint64(file);
    o.Name = readstring(file);
    o.Signature = readstring(file);
    return o;
}

static ReadScriptMetadataMethod(file)
{
    auto o = object();
    o.Address = readint64(file);
    o.Name = readstring(file);
    o.MethodAddress = readint64(file);
    return o;
}

static ReadAddresses(file)
{
    return readint64(file);
}

static ReadArray(file, reader)
{
    auto count = readint32(file);
    msg("array: %d\n", count);
    auto array = object();
    auto i;
    for(i = 0; i < count; i = i + 1)
    {
        array[i] = reader(file);
        auto p0 = file.tell();
        auto p1 = readint64(file);
        if(p0 != p1)
        {
            msg("bad read: %d => %d | %d\n", p1, p0, i);
        }
    }
    array.len = count;
    return array;
}

static get_addr(addr)
{
    return addr + get_imagebase();
}

static make_function(start, stop)
{
    auto next_func = get_next_func(start);
    if (next_func < stop) 
    {
        stop = next_func;
    }
    if (get_func_attr(start, FUNCATTR_START) == start)
    {
        del_func(start);
    }
    add_func(start, stop);
}

static name_address(addr, name)
{
    auto ret = set_name(addr, name, SN_NOWARN | SN_NOCHECK);
    if (ret == 0)
    {
        auto new_name = sprintf("%s_%d", name, addr);
        set_name(addr, new_name, SN_NOWARN | SN_NOCHECK);
    }
}

static ReadAllText(filename)
{
    auto str;
    auto file = open_loader_input(filename, 0);
    auto len = file.size();
    file.read(&str, len);
    file.close();
    return str;
}

static LoadScriptData()
{
    auto bpath = ask_file(0, "*.bin", "script.bin");
    auto hpath = ask_file(0, "*.h", "il2cpp.h");
    msg("parse decls...\n");
    auto ne = parse_decls(ReadAllText(hpath), 0);
    msg("parse decls error count: %d\n", ne);
    
    auto bin = open_loader_input(bpath, 0);
    auto o = object();
    msg("read ScriptMethod\n");
    o.ScriptMethod = ReadArray(bin, ReadScriptMethod);
    msg("read ScriptString\n");
    o.ScriptString = ReadArray(bin, ReadScriptString);
    msg("read ScriptMetadata\n");
    o.ScriptMetadata = ReadArray(bin, ReadScriptMetadata);
    msg("read ScriptMetadataMethod\n");
    o.ScriptMetadataMethod = ReadArray(bin, ReadScriptMetadataMethod);
    msg("read Addresses\n");
    o.Addresses = ReadArray(bin, ReadAddresses);
    bin.close();
    return o;
}

static main()
{
    auto data = LoadScriptData();
    auto i, array, len;
    auto item, addr, name;
    
    //Addresses
    msg("data.Addresses (1 / 5)...\n");
    array = data.Addresses;
    len = array.len - 1;
    for(i = 0; i < len; i = i + 1)
    {
        auto start = get_addr(array[i]);
        auto stop = get_addr(array[i + 1]);
        make_function(start, stop);
    }
    
    //ScriptMethod
    msg("data.ScriptMethod (2 / 5)...\n");
    array = data.ScriptMethod;
    len = array.len;
    for(i = 0; i < len; i = i + 1)
    {
        item = array[i];
        addr = get_addr(item.Address);
        name_address(addr, item.Name);
        auto signature = parse_decl(item.Signature, 0);
        if (signature == 0)
        {
            msg("parse_decl failed: %s\n", item.Signature);
        }
        else if (apply_type(addr, signature, 1) == 0)
        {
            msg("apply_type failed: [0x%X] %s\n", addr, item.Signature);
        }
    }
    
    //Make String
    msg("data.ScriptString (3 / 5)...\n");
    array = data.ScriptString;
    len = array.len;
    for(i = 0; i < len; i = i + 1)
    {
        item = array[i];
        auto text = item.Value;
        addr = get_addr(item.Address);
        name = sprintf("StringLiteral_%d", i);
        set_name(addr, name, SN_NOWARN);
        set_cmt(addr, text, 1);
    }
    
    //ScriptMetadata
    msg("data.ScriptMetadata (4 / 5)...\n");
    array = data.ScriptMetadata;
    len = array.len;
    for(i = 0; i < len; i = i + 1)
    {
        item = array[i];
        name = item.Name;
        addr = get_addr(item.Address);
        name_address(addr, name);
        set_cmt(addr, name, 1);
        if (item.Signature != "")
        {
            signature = parse_decl(item.Signature, 0);
            if (signature == 0)
            {
                msg("parse_decl failed: %s\n", item.Signature);
            }
            else if (apply_type(addr, signature, 1) == 0)
            {
                msg("apply_type failed: [0x%X] %s\n", addr, item.Signature);
            }
        }
    }
    
    //ScriptMetadataMethod
    msg("data.ScriptMetadataMethod (5 / 5)...\n");
    array = data.ScriptMetadataMethod;
    len = array.len;
    for(i = 0; i < len; i = i + 1)
    {
        item = array[i];
        name = item.Name;
        addr = get_addr(item.Address);
        auto methodAddr = get_addr(item.MethodAddress);
        name_address(addr, name);
        set_cmt(addr, name, 1);
        set_cmt(addr, sprintf("0x%X", methodAddr), 0);
    }
    
    msg("======done======\n");
    msg("==Il2CppDumper==\n");
    msg("======idc=======\n");
}