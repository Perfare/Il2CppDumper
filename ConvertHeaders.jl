function NewHeaders(OldFilePath)
  io = open(OldFilePath*"il2cpp.h", "r")
  Contents = read(io, String)
  close(io)
 
  Contents = replace(Contents, "uintptr_t" => "void*",
                               "intptr_t"  => "void*",
                               "int32_t _int32;" => "int32_t _field_int32;")

  io = open(OldFilePath*"il2cpp_binja.h", "w")
  print(io, Contents)
  close(io)
end
