현재 해당 레포지토리로 생성된 프로그램은 당신도 알다시피 Il2CppDumper.exe 실행을 통하여 GameAssembly.dll 및 global-metadata.dat 를 활용 하여 덤프 파일을 생성하는것입니다.

최근 이 프로그램에 한계점을 발견하였습니다. 맞습니다, 당신이 해야할 과제가 바로 '한계점 돌파' 입니다.
이 프로그램은 global-metadata.dat 의 용량이 늘어나면 Overflow 현상이 발생합니다. 그리고 작업이 불가능합니다. 아래는 실패 당시의 로그기록이며 분석 후 한계점을 파악하고 돌파하시길 바랍니다. 당신을 위하여 추가적인 정보도 포함시켜 적어드리도록 하겠습니다.

::오류가 발생한 시점의 로그(전체본)::
```
Initializing metadata...
Metadata Version: 31
Initializing il2cpp file...
Il2Cpp Version: 31
Searching...
CodeRegistration : 189c98b20
MetadataRegistration : 18bf148a0
System.OverflowException: Arithmetic operation resulted in an overflow.
   at Il2CppDumper.BinaryStream.ReadClassArray[T](Int64 count) in C:\projects\il2cppdumper\Il2CppDumper\IO\BinaryStream.cs:line 187
   at Il2CppDumper.Il2Cpp.Init(UInt64 codeRegistration, UInt64 metadataRegistration) in C:\projects\il2cppdumper\Il2CppDumper\Il2Cpp\Il2Cpp.cs:line 162
   at Il2CppDumper.Il2Cpp.AutoPlusInit(UInt64 codeRegistration, UInt64 metadataRegistration) in C:\projects\il2cppdumper\Il2CppDumper\Il2Cpp\Il2Cpp.cs:line 114
   at Il2CppDumper.PE.PlusSearch(Int32 methodCount, Int32 typeDefinitionsCount, Int32 imageCount) in C:\projects\il2cppdumper\Il2CppDumper\ExecutableFormats\PE.cs:line 88
   at Il2CppDumper.Program.Init(String il2cppPath, String metadataPath, Metadata& metadata, Il2Cpp& il2Cpp) in C:\projects\il2cppdumper\Il2CppDumper\Program.cs:line 210
ERROR: An error occurred while processing.
```

::정상 출력 로그(전체본)::
```
Initializing metadata...
Metadata Version: 24.1
Initializing il2cpp file...
Il2Cpp Version: 24.1
Searching...
CodeRegistration : 183baa660
MetadataRegistration : 183baad50
Dumping...
Done!
Generate struct...
Done!
Generate dummy dll...
Done!
Press any key to exit...
```

::정상로그를 발생시킨 global-metadata.dat의 매직, 오프셋 카운트::
```
Magic: 0xFAB11BAF
Metadata Version: 24
String Literal Offset: 0x00005BF8, Count: 3392748
MethodDef Offset: 0x00A9FC20, Count: 367132
TypeDef Offset: 0x0069F0D8, Count: 10810344
```

::오류로그를 발생시킨 global-metadata.dat의 매직, 오프셋 카운트::
```
Magic: 0xFAB11BAF
Metadata Version: 31
String Literal Offset: 0x00000E58, Count: 10301012
MethodDef Offset: 0x015EA7E8, Count: 183320
TypeDef Offset: 0x00A98F00, Count: 22545304
```

고용량 처리도 될 수 있으며 StackOverflow 현상을 완전히 수정하십시오.