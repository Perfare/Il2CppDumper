# Il2CppDumper
[![Build status](https://ci.appveyor.com/api/projects/status/anhqw33vcpmp8ofa?svg=true)](https://ci.appveyor.com/project/Perfare/il2cppdumper/branch/master/artifacts)  
从il2cpp中获取types, methods, fields等等数据  
基础逻辑代码来源于[Il2CppDumper](https://github.com/Jumboperson/Il2CppDumper)  

## 功能
* 支持ELF(arm, x86), Mach-O(32bit, 64bit)
* 支持Metadata版本16, 20, 21, 22, 23, 24
* 导出包括types, fields, properties, methods, attributes
* 自动生成IDA脚本(重命名methodName和添加stringLiteral注释)

## 使用说明
运行Il2CppDumper.exe并依次选择il2cpp的可执行文件（ELF或者Mach-O文件）和global-metadata.dat文件，然后选择运行的模式，将生成dump.cs文件和script.py脚本

### 关于模式
#### Manual
你需要手动输入CodeRegistration和MetadataRegistration的指针地址，一般需要依靠反汇编工具来获取地址
#### Auto
原理是通过函数的特征字节找到il2cpp_codegen_register函数并获取传入il2cpp::vm::MetadataCache::Register中的参数1（CodeRegistration）和参数2（MetadataRegistration）。不过由于不同编译器编译出来的结果有差异，对于不常见的形式将无法正常工作。
#### Auto(Advanced)
支持Metadata 20及以后的版本，在16版本下只能获取到CodeRegistration地址，利用指针特征进行搜索，通用性比Auto强。
#### Auto(Plus)
支持Metadata 20及以后的版本，在16版本下只能获取到CodeRegistration地址，以metadata的数据作为依据，指针特征作为判读条件进行搜索，对于某些文件处理的比Auto(Advanced)好。

### 关于dump.cs
作为文本文件打开即可

### 关于script.py
需要安装IDA所需的python。在IDA中File-Script file选择script.py运行即可，会重命名methodName和添加stringLiteral注释

### 关于DummyDll
利用Mono.Cecil生成的仿制Dll，完善中，目前输出：types, fields, properties, methods  
只支持使用[dnSpy](https://github.com/0xd4d/dnSpy)打开

### 关于config.json
`dumpmethod`，`dumpfield`，`dumpproperty`，`dumpattribute`，`dumpfieldoffset`  
控制程序是否在dump.cs输出相应的内容  

`forceil2cppversion`，`forceversion`  
当forceil2cppversion为true时，程序将根据forceversion指定的版本读取il2cpp的可执行文件（Metadata仍然使用header里的版本），这在部分低版本的il2cpp中将会有用（比如安卓20版本下，你可能需要设置forceversion为16程序才能正常工作）  

## 常见问题
#### `ERROR: Metadata file supplied is not valid metadata file.`  
正如它所显示的，你选择的global-metadata.dat不是一个有效的metadata文件，通常是因为游戏加密了global-metadata.dat文件。关于解密的问题最好去破解论坛寻求帮助，请不要在issues提问！  

#### `ERROR: Unable to process file automatically, try to use other mode.`  
当两种自动模式都无法工作时，你可以打开一个新的issue，并上传文件，我会尝试解决
