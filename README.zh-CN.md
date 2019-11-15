# Il2CppDumper

[![Build status](https://ci.appveyor.com/api/projects/status/anhqw33vcpmp8ofa?svg=true)](https://ci.appveyor.com/project/Perfare/il2cppdumper/branch/master/artifacts)

从Unity il2cpp文件还原DLl（代码除外）

## 功能
* 完整还原除代码以外的DLL信息
* 支持ELF, ELF64, Mach-O, PE和NSO格式
* 支持Unity 5.3及更高版本
* 自动生成IDA脚本
  * 重命名函数
  * 重命名并注释Metadata
  * MakeFunction完善IDA分析
* 支持dump的安卓.so文件以绕过保护

## 使用说明

```
Il2CppDumper.exe <executable-file> <global-metadata> [unityVersion] [mode]
```

或者直接运行Il2CppDumper.exe并依次选择il2cpp的可执行文件和global-metadata.dat文件，然后根据提示输入相应信息。

将在程序运行目录下生成输出文件

### 关于模式
#### Manual
你需要手动输入`CodeRegistration`和`MetadataRegistration`的指针地址，一般需要依靠反汇编工具来获取地址
#### Auto
通过函数的特征字节找到`il2cpp_codegen_register`函数并获取传入`il2cpp::vm::MetadataCache::Register`中的参数1（`CodeRegistration`）和参数2（`MetadataRegistration`）。由于不同编译器优化差异，很多情况下无法正常工作。
#### Auto(Plus) - **优先使用此模式**
以metadata的数据作为依据，指针特征作为判读条件进行搜索。

支持Metadata版本20及以后版本

在16版本下只能获取到`CodeRegistration`地址

#### Auto(Symbol)
只支持ELF，使用自带的符号进行处理。

### 输出文件

#### dump.cs
简单的反编译代码，推荐使用[dnSpy](https://github.com/0xd4d/dnSpy)或者其他工具从DummyDll获取更完善的代码

#### script.py
需要安装IDA所需的python。在IDA中File-Script file选择script.py运行即可，会重命名methodName，添加stringLiteral注释和MakeFunction

#### stringliteral.json
包含所有stringLiteral信息

#### DummyDll
文件夹，包含所有还原的DLL文件

### 关于config.json
* `DumpMethod`，`DumpField`，`DumpProperty`，`DumpAttribute`，`DumpFieldOffset`, `DumpMethodOffset`, `DumpTypeDefIndex`
  * 是否在dump.cs输出相应的内容

* `DummyDll`
  * 是否生成DummyDll

* `MakeFunction`
  * 是否在script.py中添加MakeFunction代码

* `ForceIl2CppVersion`，`ForceVersion`  
  * 当ForceIl2CppVersion为true时，程序将根据ForceVersion指定的版本读取il2cpp的可执行文件（Metadata仍然使用header里的版本），在部分低版本的il2cpp中可能会用到（比如安卓20版本下，你可能需要设置ForceVersion为16程序才能正常工作）

## 常见问题
#### `ERROR: Metadata file supplied is not valid metadata file.`
global-metadata.dat不是一个有效的metadata文件，通常是因为游戏加密了global-metadata.dat文件。关于解密的问题最好去相关破解论坛寻求帮助，请不要在issues提问！

#### `ERROR: Can't use this mode to process file, try another mode.`
当所有自动模式都无法工作时，确认可执行文件未加壳或受保护后，你可以打开一个新的issue，并上传文件，我会尝试解决

## 感谢
- Jumboperson - [Il2CppDumper](https://github.com/Jumboperson/Il2CppDumper)