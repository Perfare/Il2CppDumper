# Il2CppDumper

[![Build status](https://ci.appveyor.com/api/projects/status/anhqw33vcpmp8ofa?svg=true)](https://ci.appveyor.com/project/Perfare/il2cppdumper/branch/master/artifacts)

Unity il2cpp逆向工程

## 关于此 Fork

此 Fork 针对 Unity/IL2CPP 高版本 metadata 做了实验性适配，包括 Unity 6000.x 使用的 v35/v38/v39。当前主要改动包括高版本 metadata 解析、方法地址恢复、DummyDll 生成修复，以及高版本 `il2cpp.h` 生成。

高版本适配只在少量游戏上做过自测。不同 Unity 版本、平台、项目配置和保护方式都会影响 dump 结果。如果遇到无法 dump 的游戏，需要自行调试并修改源码适配。本项目不承诺对每个游戏或每个保护壳做一一适配。

## 免责声明

本项目仅用于学习、研究、互操作分析，以及对你拥有或已获授权的软件进行分析。请勿用于侵犯版权、绕过访问控制、破坏线上服务公平性，或违反法律法规及服务条款的行为。使用本工具产生的一切后果由使用者自行承担。

## 功能

* 还原DLL文件（不包含代码），可用于提取`MonoBehaviour`和`MonoScript`
* 支持ELF, ELF64, Mach-O, PE, NSO和WASM格式
* 支持 Unity 5.3 - 2022.2，并实验性适配 Unity 高版本 metadata（如 v35/v38/v39，Unity 6000.x）
* 生成IDA和Ghidra的脚本，帮助IDA和Ghidra更好的分析il2cpp文件
* 生成结构体头文件
* 支持从内存dump的`libil2cpp.so`文件以绕过保护
* 支持绕过简单的PE保护

## 使用说明

直接运行Il2CppDumper.exe并依次选择il2cpp的可执行文件和global-metadata.dat文件，然后根据提示输入相应信息。

程序运行完成后将在当前运行目录下生成输出文件

### 命令行

```
Il2CppDumper.exe <executable-file> <global-metadata> <output-directory>
```

### 输出文件

#### DummyDll

文件夹，包含所有还原的DLL文件

使用[dnSpy](https://github.com/0xd4d/dnSpy)，[ILSpy](https://github.com/icsharpcode/ILSpy)或者其他.Net反编译工具即可查看具体信息

可用于提取Unity的`MonoBehaviour`和`MonoScript`，适用于[UtinyRipper](https://github.com/mafaca/UtinyRipper)或者[UABE](https://7daystodie.com/forums/showthread.php?22675-Unity-Assets-Bundle-Extractor)等

#### ida.py

用于IDA

#### ida_with_struct.py

用于IDA, 读取il2cpp.h文件并在IDA中应用结构信息

#### il2cpp.h

包含结构体的头文件

#### ghidra.py

用于Ghidra

#### Il2CppBinaryNinja

用于BinaryNinja

#### ghidra_wasm.py

用于Ghidra, 和[ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin)一起工作

#### script.json

用于IDA和Ghidra脚本

#### stringliteral.json

包含所有stringLiteral信息

### 关于config.json

* `DumpMethod`，`DumpField`，`DumpProperty`，`DumpAttribute`，`DumpFieldOffset`, `DumpMethodOffset`, `DumpTypeDefIndex`
  * 是否在dump.cs输出相应的内容

* `GenerateDummyDll`，`GenerateScript`
  * 是否生成这些内容

* `DummyDllAddToken`
  * 是否在DummyDll中添加token

* `RequireAnyKey`
  * 在程序结束时是否需要按键退出

* `ForceIl2CppVersion`，`ForceVersion`  
  * 当ForceIl2CppVersion为`true`时，程序将根据ForceVersion指定的版本读取il2cpp的可执行文件（Metadata仍然使用header里的版本），在部分低版本的il2cpp中可能会用到（比如安卓20版本下，你可能需要设置ForceVersion为16程序才能正常工作）

* `ForceDump`
  * 强制将文件视为dump文件

* `NoRedirectedPointer`
  * 将dump文件中的指针视为未重定向的, 从某些设备dump出的文件需要设置该项为`true`

## 常见问题

#### `ERROR: Metadata file supplied is not valid metadata file.`

global-metadata.dat已被加密。关于解密的问题请去相关破解论坛寻求帮助，请不要在issues提问！

如果你的文件是`libil2cpp.so`并且你拥有一台已root的安卓手机，你可以尝试我的另一个项目[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)，它能够无视global-metadata.dat加密

#### `ERROR: Can't use auto mode to process file, try manual mode.`

请注意PC平台的可执行文件是`GameAssembly.dll`或者`*Assembly.dll`

如果是 Unity 高版本或带保护的构建，请自行定位失败的解析路径并修改源码适配。本项目不承诺对具体游戏逐一适配。

#### `ERROR: This file may be protected.`

Il2CppDumper检测到可执行文件已被保护，使用`GameGuardian`从游戏内存中dump `libil2cpp.so`，然后使用Il2CppDumper载入按提示操作，可绕过大部分保护

如果你拥有一台已root的安卓手机，你可以尝试我的另一个项目[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)，它能够绕过几乎所有保护

## 感谢

- Jumboperson - [Il2CppDumper](https://github.com/Jumboperson/Il2CppDumper)
