import re

header = "typedef unsigned __int8 uint8_t;\n" \
         "typedef unsigned __int16 uint16_t;\n" \
         "typedef unsigned __int32 uint32_t;\n" \
         "typedef unsigned __int64 uint64_t;\n" \
         "typedef __int8 int8_t;\n" \
         "typedef __int16 int16_t;\n" \
         "typedef __int32 int32_t;\n" \
         "typedef __int64 int64_t;\n" \
         "typedef __int64 intptr_t;\n" \
         "typedef __int64 uintptr_t;\n" \
         "typedef unsigned __int64 size_t;\n" \
         "typedef _Bool bool;\n"

replace_keywords = [
    " alignas;",
    " _Alignas;",
    " alignof;",
    " _Alignof;",
    " _Atomic;",
    " auto;",
    " _BitInt;",
    " bool;",
    " _Bool;",
    " break;",
    " case;",
    " char;",
    " _Complex;",
    " const;",
    " constexpr;",
    " continue;",
    " _Decimal128;",
    " _Decimal32;",
    " _Decimal64;",
    " default;",
    " do;",
    " double;",
    " else;",
    " enum;",
    " extern;",
    " false;",
    " float;",
    " for;",
    " _Generic;",
    " goto;",
    " if;",
    " _Imaginary;",
    " inline;",
    " int;",
    " long;",
    " _Noreturn;",
    " nullptr;",
    " register;",
    " restrict;",
    " return;",
    " short;",
    " signed;",
    " sizeof;",
    " static;",
    " static_assert;",
    " _Static_assert;",
    " struct;",
    " switch;",
    " thread_local;",
    " _Thread_local;",
    " true;",
    " typedef;",
    " typeof;",
    " typeof_unqual;",
    " union;",
    " unsigned;",
    " void;",
    " volatile;",
    " while;",
]


def main():
    fixed_header_data = ""
    h_file = askFile("il2cpp.h from Il2cppdumper", "Open")
    with open(h_file.absolutePath, 'r') as f:
        print("il2cpp.h opened...")
        original_header_data = f.read()
    print("il2cpp.h read and closed.")
    fixed_header_data = re.sub(r": (\w+) {", r"{\n \1 super;", original_header_data)
    for i in range(len(replace_keywords)):
        if (fixed_header_data.find(replace_keywords[i]) != -1):
            x = 1
            while (x < 10):
                if (fixed_header_data.find(replace_keywords[i][:1] + ("_" * x) + replace_keywords[i][1:]) == -1):
                    string = replace_keywords[i][:1] + ("_" * x) + replace_keywords[i][1:]
                    break
                x += 1
            if (x == 10):
                print("Replacing variable name \"%s\" failed..." % (replace_keywords[i][1:-1]))
            else:
                fixed_header_data = fixed_header_data.replace(replace_keywords[i], string)
                print("Replace variable name \"%s\" with \"%s\"..." % (replace_keywords[i][1:-1], string[1:-1]))
    print("il2cpp.h data fixed...")
    new_file = askFile("Choose where to save patched il2cpp.h", "Save")
    with open(new_file.absolutePath, 'w') as f:
        print("Patched header opened...")
        f.write(header)
        print("Patched header common typedefs written...")
        f.write(fixed_header_data)
    print("Patched header fixed data written and closed...")


if __name__ == '__main__':
    print("Script started...")
    main()
