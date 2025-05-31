## IDA Plugins

3rd-party lists

* [onethawt/idaplugins-list: a list of IDA plugins](https://github.com/onethawt/idaplugins-list/blob/master/README.md)
* [duo-labs/idapython - Duo Labs IDAPython Repository](https://github.com/duo-labs/idapython)
* [usualsuspect/ida_stuff](https://github.com/usualsuspect/ida_stuff)
* [xrkk/awesome-ida - 跟IDA Pro有关的资源收集。当前包括的工具个数450左右，并根据功能进行了粗糙的分类。部分工具添加了中文描述](https://github.com/xrkk/awesome-ida)
* [repnz/ida-plugins - 现在就一个插件](https://github.com/repnz/ida-plugins)
* [RolfRolles/Miscellaneous](https://github.com/RolfRolles/Miscellaneous)
  * [Hex-Rays, GetProcAddress, and Malware Analysis - 分析使用GetProcessAddress()动态定位函数地址并执行的程序时，通过修改函数指针原型，提高F5的可读性](https://www.msreverseengineering.com/blog/2021/6/1/hex-rays-getprocaddress-and-malware-analysis)

IDA scripts

* [eset/ipyida - IPython console integration for IDA Pro](https://github.com/eset/ipyida)
* [gist: IDAPython - Change Function Names in IDA According to their corresponding debug prints](https://gist.github.com/0xgalz/cce0bfead8458226faddad6dd7f88350)
* [ioncodes/idacode - An integration for IDA and VS Code which connects both to easily execute and debug IDAPython scripts](https://github.com/ioncodes/idacode)
* [inforion/idapython-cheatsheet - Scripts and cheatsheets for IDAPython](https://github.com/inforion/idapython-cheatsheet)
* [0xeb/ida-qscripts - increase productivity when developing scripts for IDA - 自动重新加载脚本](https://github.com/0xeb/ida-qscripts)
* [0xeb/ida-climacros - Create and use macros in IDA's CLIs](https://github.com/0xeb/ida-climacros)
* [nirizr/idasix - IDAPython compatibility library, aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions - 2018停更](https://github.com/nirizr/idasix)
* [gist: IDAPYTHON script for patching bytes that match a regex pattern with NOPs](https://gist.github.com/alexander-hanel/faff87d25f4b2896241c8f835fa1a321)

Debugger

* [airbus-cert/ttddbg - Time Travel Debugging IDA plugin](https://github.com/airbus-cert/ttddbg)

C/C++

* [0xgalz/Virtuailor - IDAPython tool for creating automatic C++ virtual tables in IDA Pro - 需要执行一次才能完成vtable解析](https://github.com/0xgalz/Virtuailor)
* [murx-/devi - Devirtualize Virtual Calls](https://github.com/murx-/devi)
* [fboldewin/COM-Code-Helper - Two IDAPython Scripts help you to reconstruct Microsoft COM (Component Object Model) Code](https://github.com/fboldewin/COM-Code-Helper)
* [nccgroup/SusanRTTI - Another RTTI Parsing IDA plugin](https://github.com/nccgroup/SusanRTTI)
* [patois/mrspicky - An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions - 2019停更](https://github.com/patois/mrspicky)

ObjC

* [ChiChou/IDA-ObjCExplorer - Objective C classdump for IDA Pro](https://github.com/ChiChou/IDA-ObjCExplorer)

Golang

* [SentineLabs/AlphaGolang - IDApython Scripts for Analyzing Golang Binaries - 4.string_cast.py可以解决golang大段字符串的问题](https://github.com/SentineLabs/AlphaGolang)
* [sibears/IDAGolangHelper - Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary](https://github.com/sibears/IDAGolangHelper)
* [0xjiayu/go_parser - Yet Another Golang binary parser for IDAPro](https://github.com/0xjiayu/go_parser)
* [strazzere/golang_loader_assist - Making GO reversing easier in IDA Pro](https://github.com/strazzere/golang_loader_assist)

Windows driver

* [VoidSec/DriverBuddyReloaded - Driver Buddy Reloaded is an IDA Pro Python plugin that helps automate some tedious Windows Kernel Drivers reverse engineering tasks - 替代没再更新过的DriverBuddy和win_driver_plugin，能识别驱动类型、dispatch函数地址等等。定位dispatch函数地址后，右键菜单里可以decode所有ioctl类型和权限](https://github.com/VoidSec/DriverBuddyReloaded)

Code coverage

* [gaasedelen/lighthouse - Code Coverage Explorer for IDA Pro & Binary Ninja - 先用 dynamorio 工具跑个日志，然后用插件导入信息](https://github.com/gaasedelen/lighthouse)

Decompiler

* [patois/HRDevHelper - Context-sensitive HexRays decompiler plugin that visualizes the ctree of decompiled functions](https://github.com/patois/HRDevHelper)
  * https://hex-rays.com/blog/plugin-focus-hrdevhelper/
* [airbus-cert/Yagi - Yet Another Ghidra Integration for IDA](https://github.com/airbus-cert/Yagi)
* [REhints/HexRaysCodeXplorer - Hex-Rays Decompiler plugin for better code navigation](https://github.com/REhints/HexRaysCodeXplorer)
* [chrisps/Hexext - a plugin to improve the output of the hexrays decompiler through microcode manipulation - 仅支持IDA 7.0，2019停更](https://github.com/chrisps/Hexext)
* [Cisco-Talos/GhIDA - Ghidra Decompiler for IDA Pro](https://github.com/Cisco-Talos/GhIDA)
* [RevSpBird/HightLight - a plugin for ida of version 7.2 to help know F5 window codes better](https://github.com/RevSpBird/HightLight)
* [fireeye/FIDL - A sane API for IDA Pro's decompiler. Useful for malware RE and vulnerability research](https://github.com/fireeye/FIDL)
* [patois/abyss - IDAPython Plugin for Postprocessing of Hexrays Decompiler Output](https://github.com/patois/abyss)
* [alexhude/FRIEND - Flexible Register/Instruction Extender aNd Documentation](https://github.com/alexhude/FRIEND)
* [eshard/d810 - an IDA Pro plugin which can be used to deobfuscate code at decompilation time by modifying IDA Pro microcode](https://gitlab.com/eshard/d810)

Diff / Patch

* [gaasedelen/patching - An Interactive Binary Patching Plugin for IDA Pro - 比keypatch好用，但是也是一堆问题，成熟度很低；他这个也是用keystone-engine，但是需要用它改过的版本，必须得用releases里的版本](https://github.com/gaasedelen/patching)
* [keypatch0 - A replacement of the internal IDA assembler - IDA内置的汇编工具不支持64位操作，也不支持批量填充，只能用这个插件](http://www.keystone-engine.org/keypatch0)
* [joxeankoret/diaphora - the most advanced Free and Open Source program diffing tool - 1.8K star，将IDB导出为sqlite后进行对比，非常好用](https://github.com/joxeankoret/diaphora)
* [gist: ida_patcher.c - 读取 Create DIF File 产出的结果，并给二进制打补丁](https://gist.github.com/Zeex/6607437)
* [google/binnavi - a binary analysis IDE that allows to inspect, navigate, edit and annotate control flow graphs and call graphs of disassembled code](https://github.com/google/binnavi)
* [McGill-DMaS/Kam1n0-Plugin-IDA-Pro - The Kam1n0 Assembly Clone Search Engine](https://www.whitehatters.academy/diffing-with-kam1n0/)
* [ohjeongwook/DarunGrim - A Binary Diffing and Patch Analysis Tool (v3) http://darungrim.org](https://github.com/ohjeongwook/DarunGrim)
* [debasishm89/MassDiffer - Large Scale Cumulative Binary Diffing Script](https://github.com/debasishm89/MassDiffer)

Signature matching

* [OALabs/hashdb-ida - HashDB API hash lookup plugin for IDA Pro - 需要调用API，不是本地](https://github.com/OALabs/hashdb-ida)
* [Maktm/FLIRTDB - A community driven collection of IDA FLIRT signature files - 1.1K star](https://github.com/Maktm/FLIRTDB)
* [polymorf/findcrypt-yara - IDA pro plugin to find crypto constants (and more)](https://github.com/polymorf/findcrypt-yara)
* [L4ys/IDASignsrch - IDAPython Plugin for searching signatures, use xml signature database from IDA_Signsrch](https://github.com/L4ys/IDASignsrch)
* [secrary/idenLib - Library Function Identification](https://github.com/secrary/idenLib)
* [CheckPointSW/Karta - source code assisted fast binary matching plugin for IDA](https://github.com/CheckPointSW/Karta)
* [patois/HexraysToolbox - Find code patterns within the Hexrays AST](https://github.com/patois/HexraysToolbox)

UEFI 

* [kyurchenko/IDAPython-scripts-for-UEFI-analisys: Analysis of the disassembled UEFI image](https://github.com/kyurchenko/IDAPython-scripts-for-UEFI-analisys)
* [gdbinit/EFISwissKnife - An IDA plugin to improve (U)EFI reversing](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
* [binarly-io/efiXplorer - IDA plugin for UEFI firmware analysis and reverse engineering automation](https://github.com/binarly-io/efiXplorer)

CPU loader

* [gamozolabs/proc_mem_ida_loader - A /proc/mem IDA loader to snapshot a running process](https://github.com/gamozolabs/proc_mem_ida_loader)
* [RolfRolles/HiddenBeeLoader - IDA loader module for Hidden Bee's custom executable file format](https://github.com/RolfRolles/HiddenBeeLoader)
* [fireeye/idawasm - IDA Pro loader and processor modules for WebAssembly](https://github.com/fireeye/idawasm)
* [matteyeux/srom64helper - IDA loader for Apple SecureROM](https://github.com/matteyeux/srom64helper)
* [trailofbits/ida-evm - IDA Processor Module for the Ethereum Virtual Machine (EVM)](https://github.com/trailofbits/ida-evm)
* [JeremyWildsmith/x86devirt - automatically devirtualize code that has been virtualized using x86virt](https://github.com/JeremyWildsmith/x86devirt)
* [mefistotelis/ida-pro-loadmap - Plugin for IDA Pro disassembler which allows loading .map files](https://github.com/mefistotelis/ida-pro-loadmap)
* [nforest/droidimg - Android/Linux vmlinux loader](https://github.com/nforest/droidimg)

Symbol

* [KasperskyLab/Apihashes - IDA Pro plugin for recognizing known hashes of API function names](https://github.com/KasperskyLab/Apihashes)
* [a1ext/auto_re - IDA PRO auto-renaming plugin with tagging support](https://github.com/a1ext/auto_re)
* [joxeankoret/idamagicstrings - An IDA Python script to extract information from string constants](https://github.com/joxeankoret/idamagicstrings)
* [danigargu/deREferencing - implements more user-friendly register and stack views - 在stack view里增加字符串展示，很有用](https://github.com/danigargu/deREferencing)
* [ida-arm-system-highlight - Decoding ARM system instructions](https://github.com/gdelugre/ida-arm-system-highlight)
* [oct0xor/highlight2 - changes color of call instructions and works with all architectures](https://github.com/oct0xor/highlight2)
* [dayzerosec/IDA-Android-Kernel-Symbolizer - An IDA plugin that allows you to use /proc/kallsyms output to import function and data labels into an extracted Android kernel image](https://github.com/dayzerosec/IDA-Android-Kernel-Symbolizer)
* [TakahiroHaruyama/ida_haru - stackstring_static.py - IDAPython script statically-recovering strings constructed in stack](https://github.com/TakahiroHaruyama/ida_haru/tree/master/stackstring_static)

Emulation

* [fireeye/flare-floss - FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware - 1.9K star](https://github.com/mandiant/flare-floss)
* [bkerler/uEmu - a tiny cute emulator plugin for IDA based on unicorn engine](https://github.com/bkerler/uEmu)
* [Brandon-Everhart/AngryIDA - Python based angr plug in for IDA Pro](https://github.com/Brandon-Everhart/AngryIDA)

Synchronization

* [x64dbg/x64dbgida - Official x64dbg plugin for IDA Pro](https://github.com/x64dbg/x64dbgida)
* [a1ext/labeless - Labels/Comments synchronization between IDA PRO and dbg backend (OllyDbg1.10, OllyDbg 2.01, x64dbg), Remote memory dumping tool (including x64-bit), Python scripting tool](https://github.com/a1ext/labeless)
* [comsecuris/gdbida: a visual bridge between a GDB session and IDA Pro's disassembler](https://github.com/comsecuris/gdbida)
* [Mixaill/FakePDB - Tool for PDB generation from IDA Pro database - 可以导给 WinDBG 用](https://github.com/Mixaill/FakePDB)
* [IDArlingTeam/IDArling - Collaborative Reverse Engineering plugin for IDA Pro & Hex-Rays](https://github.com/IDArlingTeam/IDArling/)

Unpacking

* [DavidKorczynski/RePEconstruct - a tool for automatically unpacking binaries and rebuild the binaries in a manner well-suited for further analysis, specially focused on further manual analysis in IDA pro.](https://github.com/DavidKorczynski/RePEconstruct)
* [danielplohmann/apiscout - simplifying Windows API import recovery on arbitrary memory dumps](https://github.com/danielplohmann/apiscout)

Plugin development

* [0xKira/api_palette - A code-searching/completion tool, for IDA APIs](https://github.com/0xKira/api_palette)
* [sibears/HRAST - PoC of modifying HexRays AST - 可以优化decompiler结果](https://github.com/sibears/HRAST)

Database tools

* [pr701/idb3 - Library for reading IDA Pro databases](https://github.com/pr701/idb3)

Uncategorized

* [JonathanSalwan/Triton - a dynamic binary analysis library. Build your own program analysis tools, automate your reverse engineering, perform software verification or just emulate code - 2.6K star](https://github.com/JonathanSalwan/Triton)
* [cellebrite-labs/ida_kcpp - An IDAPython module for enhancing c++ support on top of ida_kernelcache](https://github.com/cellebrite-labs/ida_kcpp)
* [FelixBer/FindFunc - an IDA PRO plugin to find code functions that contain a certain assembly or byte pattern, reference a certain name or string, or conform to various other constraints](https://github.com/FelixBer/FindFunc)
* [Accenture/VulFi - provide a single view with all cross-references to the most interesting functions (such as strcpy, sprintf, system, etc.)](https://github.com/Accenture/VulFi)
* [herosi/CTO - Call Tree Overviewer](https://github.com/herosi/CTO)
* [mcdulltii/obfDetect - IDA plugin to pinpoint obfuscated code](https://github.com/mcdulltii/obfDetect)
* [gaasedelen/tenet - A Trace Explorer for Reverse Engineers](https://github.com/gaasedelen/tenet)
* [patois/dsync - IDAPython plugin that synchronizes disassembler and decompiler views - 比自带的同步多了个代码提示](https://github.com/patois/dsync)
* [tenable/mIDA - extracts RPC interfaces and recreates the associated IDL file](https://github.com/tenable/mIDA)
* [gaasedelen/lucid - An Interactive Hex-Rays Microcode Explorer](https://github.com/gaasedelen/lucid)
* [L4ys/LazyIDA - Make your IDA Lazy!](https://github.com/L4ys/LazyIDA)
* [Cisco-Talos/DynDataResolver - 多个功能，具体看博客](https://github.com/Cisco-Talos/DynDataResolver)
* [nccgroup/idahunt - a framework to analyze binaries with IDA Pro and hunt for things in IDA Pro](https://github.com/nccgroup/idahunt)
* [Ga-ryo/IDAFuzzy - Fuzzy search tool for IDA Pro](https://github.com/Ga-ryo/IDAFuzzy)
* [ampotos/dynStruct - Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone](https://github.com/ampotos/dynStruct)
* [IDA StringCluster - extending IDA's string navigation capabilities - IDA7.5不兼容，得改改](https://github.com/Comsecuris/ida_strcluster)
* [1111joe1111/ida_ea - A set of exploitation/reversing aids for IDA: Context Viewer, Instuction Emulator, Heap Explorer, Trace Dumper, CMD and Restyle](https://github.com/1111joe1111/ida_ea)
* [ALSchwalm/dwarfexport - Export dwarf debug information from IDA Pro](https://github.com/ALSchwalm/dwarfexport)
* [maddiestone/IDAPythonEmbeddedToolkit - IDAPython scripts for automating analysis of firmware of embedded devices](https://github.com/maddiestone/IDAPythonEmbeddedToolkit)
* [tkmru/nao - Simple No-meaning Assembly Omitter for IDA Pro (This is just a prototype)](https://github.com/tkmru/nao)
* [airbus-cert/etwbreaker - An IDA plugin to deal with Event Tracing for Windows (ETW)](https://github.com/airbus-cert/etwbreaker)
* [lucasg/findrpc - carve binary for internal RPC structures](https://github.com/lucasg/findrpc)
* [andreafioraldi/IDAngr - Use angr in the IDA Pro debugger generating a state from the current debug session](https://github.com/andreafioraldi/IDAngr)
* [fireeye/flare-ida - IDA Pro utilities from FLARE team](https://github.com/fireeye/flare-ida)
* [deepinstinct/dsc_fix - Aids in reverse engineering libraries from dyld_shared_cache in IDA](https://github.com/deepinstinct/dsc_fix)
* [danigargu/heap-viewer - An IDA Pro plugin to examine the glibc heap, focused on exploit development](https://github.com/danigargu/heap-viewer)
* [endgameinc/xori - an automation-ready disassembly and static analysis library that consumes shellcode or PE binaries and provides triage analysis data](https://github.com/endgameinc/xori)
* [xerub/idastuff](https://github.com/xerub/idastuff)
* [NeatMonster/AMIE - A Minimalist Instruction Extender](https://github.com/NeatMonster/AMIE)
* [lucasg/idamagnum - a plugin for integrating MagnumDB requests within IDA](https://github.com/lucasg/idamagnum)
* [RolfRolles/HexRaysDeob - Hex-Rays microcode API plugin for breaking an obfuscating compiler](https://github.com/RolfRolles/HexRaysDeob)

## Resources

Resources

* [Analyzing an IDA Pro anti-decompilation code](https://antonioparata.blogspot.com/2022/01/analyzing-ida-pro-anti-decompilation.html)
* [youtube: IDA Pro Reverse Engineering Tutorial for Beginners](https://www.youtube.com/playlist?list=PLKwUZp9HwWoDDBPvoapdbJ1rdofowT67z)
* [ptsecurity: IDA Pro Tips to Add to Your Bag of Tricks](https://swarm.ptsecurity.com/ida-pro-tips/)

Leaked installer

* [jas502n/IDA_Pro_7.2 - 2019年泄漏版本，IDAPRONM Windows + HEXX64](https://github.com/jas502n/IDA_Pro_7.2)
* [2017年泄露的7.0版本，IDAPRONM Mac + 4 decompilers，密码 qY2jts9hEJGy](http://1024rd.com/ida-pro-7-0-all-decompilers-full-leak-pass)
   * [fjh658/IDA7.0_SP - IDA 7.0 在Mac上会偶尔崩溃。已经用不到了，留个记录吧](https://github.com/fjh658/IDA7.0_SP)
