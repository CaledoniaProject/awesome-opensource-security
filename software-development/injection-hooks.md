# Process injection / DLL injection

Uncategorized

* [momo5502/ept-hook-detection - Different aproaches to detecting EPT hooks](https://github.com/momo5502/ept-hook-detection)
* [rajiv2790/FalconEye - Real-time detection software for Windows process injections](https://github.com/rajiv2790/FalconEye)
* [ChaitanyaHaritash/Callback_Shellcode_Injection - POCs for Shellcode Injection via Callbacks](https://github.com/ChaitanyaHaritash/Callback_Shellcode_Injection)
* [sevagas/weaponize_process_injection_windows_SIGSEGv2_2019 - 介绍了一些隐蔽的代码注入方式，没有给代码，未测试](https://github.com/sevagas/weaponize_process_injection_windows_SIGSEGv2_2019)
* [0xcpu/exthost - A POC for Windows Extension Host hooking](https://github.com/0xcpu/exthost)
* [vector-sec/a049bf12da619d9af8f9c7dbd28d3b56 - PowerShell script to enumerate all Process and Thread tokens](https://gist.github.com/vector-sec/a049bf12da619d9af8f9c7dbd28d3b56)
* [lanoox/luject - A static injector of dynamic library for application (android, iphoneos, macOS, windows, linux)](https://github.com/lanoox/luject)
* [johnjohnsp1/RegistrationFreeCOM - Inject DLL Prototype using Microsoft.Windows.ACTCTX COM Object](https://github.com/johnjohnsp1/RegistrationFreeCOM)
  * [johnjohnsp1/WindowsScriptHostExtension - Extend WSH functionality with Registration-Free COM](https://github.com/johnjohnsp1/WindowsScriptHostExtension)
* [alphaSeclab/injection-stuff - PE Injection、DLL Injection、Process Injection、Thread Injection、Code Injection、Shellcode Injection、ELF Injection、Dylib Injection, including 400+Tools and 350+posts - 2020停更](https://github.com/alphaSeclab/injection-stuff)
* [mactec0/Kernelmode-manual-mapping-through-IAT - Manual mapping without creating any threads, with rw only access](https://github.com/mactec0/Kernelmode-manual-mapping-through-IAT)

Application hooks

* [Zeex/subhook - a super-simple hooking library for C and C++ that works on Windows, Linux and macOS. It supports x86 only (32-bit and 64-bit)](https://github.com/Zeex/subhook)
* [Kelvinhack/ThreadSpy - hardware assisted thread hijacker, it hijacks all executing thread on-the-fly without hooking any bytes of instruction, you can inject all kind of code or R/W memory in the desired process context for any purpose](https://github.com/Kelvinhack/ThreadSpy)
* [tandasat/DdiMon - a hypervisor performing inline hooking that is invisible to a guest (ie, any code other than DdiMon) by using extended page table (EPT)](https://github.com/tandasat/DdiMon)
* [tinysec/iathook - windows kernelmode and usermode IAT hook](https://github.com/tinysec/iathook)
* [gdabah/distormx - The ultimate hooking library](https://github.com/gdabah/distormx)
* [stevemk14ebr/PolyHook - x86/x64 C++ Hooking Library](https://github.com/stevemk14ebr/PolyHook)
* [tandasat/DotNetHooking - Sample use cases of the .NET native code hooking technique](https://github.com/tandasat/DotNetHooking)
* [secrary/Hooking-via-InstrumentationCallback](https://github.com/secrary/Hooking-via-InstrumentationCallback)
* [EasyHook - The reinvention of Windows API Hooking - 这个是.NET库，可以挂钩非.NET函数；还支持ACL，决定哪些线程走Hook](https://github.com/EasyHook/EasyHook)
* [int0/ProcessIsolator - Utility to hook SSDT of specific process and transfer control to a service (usermode app) for handling to determine action allow/deny API call etc](https://github.com/int0/ProcessIsolator)
* [citronneur/detours.net - Hook native API with C#](https://github.com/citronneur/detours.net)
* [wbenny/DetoursNT - Detours with just single dependency - NTDLL](https://github.com/wbenny/DetoursNT)
* [nektra/Deviare-InProc - a code interception engine](https://github.com/nektra/Deviare-InProc)
* [tuian/memMITM - SSL In Memory Inspection - 挂钩sspicli!DecryptMessage](https://github.com/tuian/memMITM)
* [m0n0ph1/IAT-Hooking-Revisited - Import address table (IAT) hooking is a well documented technique for intercepting calls to imported functions](https://github.com/m0n0ph1/IAT-Hooking-Revisited)
* [manicstreetcoders/AppInitGlobalHooks-Mimikatz - 基于mhook，NtQuerySystemInformation隐藏例子](https://github.com/manicstreetcoders/AppInitGlobalHooks-Mimikatz)
* [TsudaKageyu/minhook - The Minimalistic x86/x64 API Hooking Library for Windows - zloader 在用的，但是看2017停更了](https://github.com/TsudaKageyu/minhook)
  * [Sentinel-One/minhook - The Minimalistic x86/x64 API Hooking Library for Windows](https://github.com/Sentinel-One/minhook)

Unhook

* [TomOS3/UserModeUnhooking - This project is created for research into antivirus evasion by unhooking](https://github.com/TomOS3/UserModeUnhooking)
* [mgeeky/UnhookMe - an universal Windows API resolver & unhooker addressing problem of invoking unmonitored system calls from within of your Red Teams malware](https://github.com/mgeeky/UnhookMe)
* [NtRaiseHardError/AntiHook - PoC designed to evade userland-hooking anti-virus](https://github.com/NtRaiseHardError/AntiHook)
* [Kharos102/NtdllUnpatcher - Example code for EDR bypassing](https://github.com/Kharos102/NtdllUnpatcher)
* [mdsecactivebreach/firewalker - 定位JMP回来的地址，直接call；博客里介绍了现有的3种绕过hook方法](https://github.com/mdsecactivebreach/firewalker)
* [jackullrich/memfuck - A PoC designed to bypass all usermode hooks in a WoW64 environment](https://github.com/jackullrich/memfuck)
* C#
  * [MakoSec/MalwareDev - main/manual-map-csharp.cs - 测试有效，无影响](https://github.com/MakoSec/MalwareDev/blob/main/manual-map-csharp.cs)
  * [GetRektBoy724/SharpUnhooker - C# Based Universal API Unhooker - 这个是遍历IAT，效率稍微低一些](https://github.com/GetRektBoy724/SharpUnhooker)

UNIX / Linux

* [kubo/funchook - Hook function calls by inserting jump instructions at runtime - 目前最好用的Linux用户态inline hook框架，支持任意地址hook；作者不认为默认应该增加-fPIC，编译时候需要手动指定-DCMAKE_POSITION_INDEPENDENT_CODE=ON才行，呵呵](https://github.com/kubo/funchook)
* [Hackerl/pangolin - Based on project mandibule, separate shellcode from injector](https://github.com/Hackerl/pangolin)
* [SoldierX/libhijack - FreeBSD Code Injection Swiss Army Knife](https://github.com/SoldierX/libhijack)
* [emptymonkey/sigsleeper - Inject shellcode into running processes in Linux](https://github.com/emptymonkey/sigsleeper)
* [ixty/mandibule - linux elf injector for x86 x86_64 arm arm64 - 通过 /proc/PID/auxv 定位 argv 地址，然后实现ELF参数控制；其他原理类似 libreflect](https://github.com/ixty/mandibule)
* [rapid7/mettle/libreflect - ELF内存加载，支持低版本内核，但是不支持UPX程序](https://github.com/rapid7/mettle/tree/master/libreflect)
* [bediger4000/userlandexec - userland exec for Linux x86_64 - 2017停更](https://github.com/bediger4000/userlandexec)
  * [Introducing SHELF Loading - 2021年的介绍文章，说是增加了静态和PIE文件的支持](https://tmpout.sh/1/10/)
* [DavidBuchanan314/dlinject - Inject a shared library (i.e. arbitrary code) into a live linux process, without ptrace - Python实现，需要重写](https://github.com/DavidBuchanan314/dlinject)
* [brainsmoke/ptrace-burrito - a friendly wrapper around ptrace](https://github.com/brainsmoke/ptrace-burrito)
* [kubo/plthook - Hook function calls by replacing PLT(Procedure Linkage Table) entries](https://github.com/kubo/plthook)
* [AonCyberLabs/Cexigua - Linux based inter-process code injection without ptrace(2)](https://github.com/AonCyberLabs/Cexigua)
* [pmem/syscall_intercept - The system call intercepting library](https://github.com/pmem/syscall_intercept)
* [marekzmyslowski/libfiowrapper - Library to wrap all file calls when fuzzing with AFL++](https://github.com/marekzmyslowski/libfiowrapper)
* [devttys0/botox - When the ELF file is loaded, this will immediately pause execution until a SIGCONT signal is sent to the process, at which point execution resumes from the ELF's original entry point](https://github.com/devttys0/botox)
* [vikasnkumar/hotpatch - Hot patching executables on Linux using .so file injection](https://github.com/vikasnkumar/hotpatch)
* [ConnorNelson/pypreload - LD_PRELOAD, but for Python](https://github.com/ConnorNelson/pypreload)

Mac

* [cedowens/Inject_Dylib - Swift code to programmatically perform dylib injection](https://github.com/cedowens/Inject_Dylib)
* [Tyilo/insert_dylib - Command line utility for inserting a dylib load command into a Mach-O binary - dyib依赖注入](https://github.com/Tyilo/insert_dylib)
* [scen/osxinj - osx dylib injection](https://github.com/scen/osxinj)
* [rentzsch/mach_inject - interprocess code injection for Mac OS X - 2016停更](https://github.com/rentzsch/mach_inject)
* [wzqcongcong/macSubstrate - Substrate for macOS](https://github.com/wzqcongcong/macSubstrate)
* [trustedsec: MacOS Injection via Third-Party Frameworks - .NET core 程序默认创建调试管道，可以直接注入代码，且不能通过开启hardened runtime关闭。](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)

Windows DLL side loading

* [Cracked5pider/earlycascade-injection - early cascade injection PoC based on Outflanks blog post](https://github.com/Cracked5pider/earlycascade-injection)
* [paranoidninja/Proxy-DLL-Loads - TpAllocWork实现DLL加载](https://github.com/paranoidninja/Proxy-DLL-Loads)
* [Save the Environment (Variable) - SYSTEMROOT环境变量实现DLL劫持](https://www.wietzebeukema.nl/blog/save-the-environment-variables)
* [tastypepperoni/RunAsWinTcb - uses an userland exploit to run a DLL with a protection level of WinTcb-Light - golang实现，项目里的API调用很参考价值；这个KnownDlls漏洞在Windows 10 21H2 10.0.19044.1826版本修复(2022.07.24)](https://github.com/tastypepperoni/RunAsWinTcb)
* [monoxgas/Koppeling - Adaptive DLL hijacking / dynamic export forwarding](https://github.com/monoxgas/Koppeling)
* [anhkgg/SuperDllHijack - 一种通用Dll劫持技术，不再需要手工导出Dll的函数接口了](https://github.com/anhkgg/SuperDllHijack)
* [tothi/dll-hijack-by-proxying - Exploiting DLL Hijacking by DLL Proxying Super Easily](https://github.com/tothi/dll-hijack-by-proxying)
* [Flangvik/SharpDllProxy - Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading - 这个是把所有函数都劫持到一个地方去了，不太适合实战使用](https://github.com/Flangvik/SharpDllProxy)
* Dll hijack discovery
  * [xforcered/WFH - Windows Feature Hunter (WFH) is a proof of concept python script that uses Frida, a dynamic instrumentation toolkit, to assist in potentially identifying common “vulnerabilities” or “features” within Windows executables. WFH currently has the capability to automatically identify potential Dynamic Linked Library (DLL) sideloading and Component Object Model (COM) hijacking opportunities at scale](https://github.com/xforcered/WFH)
  * [sensepost/rattler - Automated DLL Enumerator](https://github.com/sensepost/rattler)
  * [MojtabaTajik/Robber - Robber is open source tool for finding executables prone to DLL hijacking](https://github.com/MojtabaTajik/Robber)
  * [DinoBytes/dylib_hijack_scanner - Simple utility used to scan a directory for possibly dylib hijacks](https://github.com/DinoBytes/dylib_hijack_scanner)
* [xpnsec: Object Overloading - 模拟Windows目录结构，挂起进程后，使用NtSetInformationProcess(ProcessDeviceMap)或者SetDllDirectoryA设置DLL加载路径，然后实现类似DLL劫持事情](https://blog.xpnsec.com/object-overloading/)  

Windows .NET

* [BambiZombie/ThreadlessSpawn - 通过消息机制去触发被hook的函数，因为创建了进程，就暂且叫它ThreadlessSpawn吧](https://github.com/BambiZombie/ThreadlessSpawn)
* [Tw1sm/SharpInjector - Flexible C# shellcode runner - 这个有CreateFiber的例子](https://github.com/Tw1sm/SharpInjector)
* [plackyhacker/Shellcode-Injection-Techniques - A collection of C# shellcode injection techniques. All techniques use an AES encrypted meterpreter payload. I will be building this project up as I learn, discover or develop more techniques. Some techniques are better than others at bypassing AV](https://github.com/plackyhacker/Shellcode-Injection-Techniques)
* [enkomio/ManagedInjector - A C# DLL injection library](https://github.com/enkomio/ManagedInjector)
* [0xyg3n/PEx64-Injector - Inject your x64 bit executable to any process, masking it as a legitimate process for Anti-Virus evasion - ZwUnmapViewOfSection C#实现](https://github.com/0xyg3n/PEx64-Injector)
* [FuzzySecurity/Dendrobate - a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code](https://github.com/FuzzySecurity/Dendrobate)
* [unknownv2/CoreHook - A library that simplifies intercepting application function calls using managed code and the .NET Core runtime](https://github.com/unknownv2/CoreHook)
* [guitmz/msil-cecil-injection - Injection of MSIL using Cecil - 这个只是demo，而且是人工改IL](https://github.com/guitmz/msil-cecil-injection)
* [badBounty/directInjectorPOC - Small POC written in C# that performs shellcode injection on x64 processes using direct syscalls as a way to bypass user-land EDR hooks](https://github.com/badBounty/directInjectorPOC)
* [DamonMohammadbagher/NativePayload_TId - 有个NtCreateThreadEx例子，代码里废话太多了](https://github.com/DamonMohammadbagher/NativePayload_TId)
* [am0nsec/SharpHellsGate - C# Implementation of the Hell's Gate VX Technique](https://github.com/am0nsec/SharpHellsGate)
* [pwndizzle/c-sharp-memory-injection - A set of scripts that demonstrate how to perform memory injection in C#](https://github.com/pwndizzle/c-sharp-memory-injection)
* [jonatan1024/clrinject - Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process](https://github.com/jonatan1024/clrinject)
* [CameronAavik/ILject - Provides a way which you can load a .NET dll/exe from disk, modify/inject IL, and then run the assembly all in memory without modifying the file](https://github.com/CameronAavik/ILject)
* [djhohnstein/.NET-Profiler-DLL-Hijack - Implementation of the .NET Profiler DLL hijack in C#](https://github.com/djhohnstein/.NET-Profiler-DLL-Hijack)
* [marcin-chwedczuk/dll-inject - Simple DLL injector written in C#](https://github.com/marcin-chwedczuk/dll-inject)
* [ambray/ProcessHollowing - Simple Process Hollowing in C#](https://github.com/ambray/ProcessHollowing)
* [SolomonSklash/SyscallPOC - Shellcode injection POC using syscalls - 更底层的注入、内存API pinvoke示例](https://github.com/SolomonSklash/SyscallPOC)
* [xpn/DotNetDebug - A simple POC to demonstrate the power of .NET debugging for injection - 使用 ICorDebug 调试 .NET 程序，然后注入代码](https://github.com/xpn/DotNetDebug)
* [Issue 1336: Windows: PPL Process Injection EoP - 修改计划任务的COM设置，通过TreatAs注入带签名的jscript.dll。之后为clipup.exe创建服务，设置SERVICE_CONFIG_LAUNCH_PROTECTED标志位并启动。PPL进程启动后会执行jscript，进一步执行任意.NET代码，实现注入](https://bugs.chromium.org/p/project-zero/issues/detail?id=1336)

Windows C++

* [SafeBreach-Labs/PoolParty - A set of fully-undetectable process injection techniques abusing Windows Thread Pools - BH23 The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools](https://github.com/SafeBreach-Labs/PoolParty)
* [ShorSec/DllNotificationInjection - A POC of a new “threadless” process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes](https://github.com/ShorSec/DllNotificationInjection)
* [NUL0x4C/AtomLdr - A DLL loader with advanced evasive features](https://github.com/NUL0x4C/AtomLdr)
* [deepinstinct/Dirty-Vanity - A POC for the new injection technique, abusing windows fork API to evade EDRs](https://github.com/deepinstinct/Dirty-Vanity)
* [mq1n/SetWinEventHook_DllInjector - Another dll injection method with SetWinEventHook API](https://github.com/mq1n/SetWinEventHook_DllInjector)
* [NtQuerySystemInformation/NlsCodeInjectionThroughRegistry - Dll injection through code page id modification in registry. Based on jonas lykk research](https://github.com/NtQuerySystemInformation/NlsCodeInjectionThroughRegistry)
* [Idov31/FunctionStomping - A new shellcode injection technique. Given as C++ header, standalone Rust program or library](https://github.com/Idov31/FunctionStomping)
* [hasherezade/process_overwriting - Process Overwriting is a PE injection technique, closely related to Process Hollowing and Module Overloading](https://github.com/hasherezade/process_overwriting)
* [RedTeamOperations/Advanced-Process-Injection-Workshop - Advanced-Process-Injection-Workshop by CyberWarFare Labs](https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop)
* [kkent030315/PageTableInjection - Code Injection, Inject malicious payload via pagetables pml4](https://github.com/kkent030315/PageTableInjection)
* [0xDivyanshu/Injector - Complete Arsenal of Memory injection and other techniques for red-teaming in Windows](https://github.com/0xDivyanshu/Injector)
* [stephenfewer/ReflectiveDLLInjection - Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process - 2013年的代码，DLL需要改造才能用，普通DLL无法反射加载](https://github.com/stephenfewer/ReflectiveDLLInjection)
  * [Reflective_dll_inject - NoMethodError undefined method 'entries' for nil:NilClass - "You can not use the dll generated by msfvenom because it is not a reflective dll"](https://github.com/rapid7/metasploit-framework/issues/10144)
  * [ExpLife0011/reflective-rewrite - rewrite StephenFewers Reflective DLL Injection to make it a little more stealthy](https://github.com/ExpLife0011/reflective-rewrite)
  * [bruteratel.com: PE Reflection: The King is Dead, Long Live the King - 修改ReflectiveLoader.c，根据PE每个节的Characteristics，设置不同的内存权限，避免出现RWX类型](https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/)
* [hasherezade/process_ghosting - Process Ghosting, a new executable image tampering attack](https://github.com/hasherezade/process_ghosting)
* [hasherezade/module_overloading - A more stealthy variant of "DLL hollowing"](https://github.com/hasherezade/module_overloading)
* [hasherezade/transacted_hollowing - Transacted Hollowing - a PE injection technique, hybrid between ProcessHollowing and ProcessDoppelgänging](https://github.com/hasherezade/transacted_hollowing)
* [aaaddress1/wowGrail - PoC: Rebuild A New Path Back to the Heaven's Gate (HITB 2021)](https://github.com/aaaddress1/wowGrail)
* [jxy-s/herpaderping - Process Herpaderping proof of concept, tool, and technical deep dive. Process Herpaderping bypasses security products by obscuring the intentions of a process](https://github.com/jxy-s/herpaderping)
* [asaurusrex/DoppelGate - relies on reading ntdll on disk to grab syscall stubs, and patches these syscall stubs into desired functions to bypass Userland Hooking](https://github.com/asaurusrex/DoppelGate)
* [JohnWoodman/stealthInjector - Injects shellcode into remote processes using direct syscalls](https://github.com/JohnWoodman/stealthInjector)
* [aaaddress1/sakeInject - Windows PE - TLS (Thread Local Storage) Injector in C/C++ - 这个是改PE的，非动态注入](https://github.com/aaaddress1/sakeInject)
* [mactec0/Kernelmode-manual-mapping-through-IAT - Manual mapping without creating any threads, with rw only access](https://github.com/mactec0/Kernelmode-manual-mapping-through-IAT)
* [suvllian/process-inject - 在Windows环境下的进程注入方法：远程线程注入、创建进程挂起注入、反射注入、APCInject、SetWindowHookEX注入](https://github.com/suvllian/process-inject)
* [am0nsec/HellsGate - Original C Implementation of the Hell's Gate VX Technique](https://github.com/am0nsec/HellsGate)
* [DrNseven/SetWindowsHookEx-Injector - SetWindowsHookEx Injector](https://github.com/DrNseven/SetWindowsHookEx-Injector)
* [NtRaiseHardError/NINA - No Injection, No Allocation x64 Process Injection Technique](https://github.com/NtRaiseHardError/NINA)
* [Cybellum/DoubleAgent - Zero-Day Code Injection and Persistence Technique](https://github.com/Cybellum/DoubleAgent)
* [Mr-Un1k0d3r/MaliciousDLLGenerator - DLL Generator for side loading attack](https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator)
* [slyd0g/DLLHijackTest - DLL and PowerShell script to assist with finding DLL hijacks](https://github.com/slyd0g/DLLHijackTest)
* [fdiskyou/injectAllTheThings - Seven different DLL injection techniques in one single project](https://github.com/fdiskyou/injectAllTheThings)
* [SafeBreach-Labs/pinjectra - Pinjectra is a C/C++ OOP-like library that implements Process Injection techniques (with focus on Windows 10 64-bit)](https://github.com/SafeBreach-Labs/pinjectra)
* [dadas190/Heavens-Gate-2.0 - Executes 64bit code from a 32bit process](https://github.com/dadas190/Heavens-Gate-2.0)
* [djhohnstein/ProcessReimaging - Process reimaging proof of concept code](https://github.com/djhohnstein/ProcessReimaging)
  * [You Can Run, But You Can’t Hide — Detecting Process Reimaging Behavior](https://posts.specterops.io/you-can-run-but-you-cant-hide-detecting-process-reimaging-behavior-e6bb9a10c40b)
* [NtRaiseHardError/Dreadnought - PoC for detecting and dumping code injection (built and extended on UnRunPE)](https://github.com/NtRaiseHardError/Dreadnought)
* [antonioCoco/Mapping-Injection - Just another Windows Process Injection - MapViewOfFile3方式](https://github.com/antonioCoco/Mapping-Injection)
* [rootm0s/Injectors - DLL/Shellcode injection techniques](https://github.com/rootm0s/Injectors)
* [theevilbit/injection - Injection techniques](https://github.com/theevilbit/injection)
* [odzhan/injection - Windows process injection methods (modexp 新研究的各种注入方式)](https://github.com/odzhan/injection)
* [vallejocc/PoC-Inject-Data-WM_COPYDATA - A tiny PoC to inject and execute code into explorer.exe with WM_SETTEXT+WM_COPYDATA+SetThreadContext](https://github.com/vallejocc/PoC-Inject-Data-WM_COPYDATA)
* [countercept/doublepulsar-usermode-injector - A utility to use the usermode shellcode from the DOUBLEPULSAR payload to reflectively load an arbitrary DLL into another process](https://github.com/countercept/doublepulsar-usermode-injector)
* [DarthTon/Xenos - Windows dll injector](https://github.com/DarthTon/Xenos)
* [Akaion/Bleak - A Windows native DLL injection library written in C# that supports several methods of injection](https://github.com/Akaion/Bleak)
* [BorjaMerino/Pazuzu - Reflective DLL to run binaries from memory](https://github.com/BorjaMerino/Pazuzu)
* [vmcall/loadlibrayy - x64 manualmapper with kernel elevation and thread hijacking capabilities](https://github.com/vmcall/loadlibrayy)
* [hlldz/APC-PPID - Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread and spoof the Parent Process](https://github.com/hlldz/APC-PPID)
* [zeroKilo/ProxyDllMaker - Tool to generate proxy dll templates](https://github.com/zeroKilo/ProxyDllMaker)
* [dismantl/ImprovedReflectiveDLLInjection - It uses bootstrap shellcode (x86 or x64) to allow calling any export of the DLL from the reflective loader - 2016停更](https://github.com/dismantl/ImprovedReflectiveDLLInjection)
* [forrest-orr/phantom-dll-hollower-poc - Phantom DLL hollowing PoC](https://github.com/forrest-orr/phantom-dll-hollower-poc)
* [Spajed/processrefund - An attempt to implement Process Doppelgänging](https://github.com/Spajed/processrefund)
* [hatRiot/DelayLoadInject - Code injection via delay load libraries - 可靠程度很低](https://github.com/hatRiot/DelayLoadInject)
* [MalwareMechanic/RISCYpacker - Process Hollowing Packer](https://github.com/MalwareMechanic/RISCYpacker)
* [codereversing/runfromreg - Run executables from the Windows registry - NtUnmapViewOfSection 方式](https://github.com/codereversing/runfromreg)
* [enigma0x3/MessageBox - PoC dlls for Task Scheduler COM Hijacking](https://github.com/enigma0x3/MessageBox)
* [3xpl01tc0d3r/ProcessInjection - This program is designed to demonstrate various process injection techniques](https://github.com/3xpl01tc0d3r/ProcessInjection)
* [fireeye: WOW64!Hooks: WOW64 Subsystem Internals and Hooking Techniques](https://www.fireeye.com/blog/threat-research/2020/11/wow64-subsystem-internals-and-hooking-techniques.html)
* [EmreOvunc/Process-Injection-Process-Hollowing-T1055.012 - Execution of the malicious code is masked under a legitimate process](https://github.com/EmreOvunc/Process-Injection-Process-Hollowing-T1055.012)

Windows Python

* [joren485/HollowProcess - Hollow Process / Dynamic Forking / RunPE injection technique implemented in Python](https://github.com/joren485/HollowProcess)

Windows driver

* [wbenny/injdrv - Windows Driver for injecting DLL into user-mode processes using APC - 未测试，说是全版本Windows支持](https://github.com/wbenny/injdrv)
  * [Bypassing the Microsoft-Windows-Threat-Intelligence Kernel APC Injection Sensor - ATP 已经有监控了，这里介绍了一些绕过思路，以及微软官方是怎么发现的，没仔细看](https://medium.com/@philiptsukerman/bypassing-the-microsoft-windows-threat-intelligence-kernel-apc-injection-sensor-92266433e0b0)
* [haidragon/KeInject - win7 apc注入不支持win10](https://github.com/haidragon/KeInject)
* [adrianyy/KeInject - Kernel LdrLoadDll injector](https://github.com/adrianyy/KeInject)

Blocking DLL

* [hacks.mozilla.org: Letting users block injected third-party DLLs in Firefox - 通过hook NtMapViewOfSection()来实现DLL注入检查](https://hacks.mozilla.org/2023/03/letting-users-block-injected-third-party-dlls-in-firefox/)

MacOS

* [tihmstar/libtakeover - call functions in a remote process using Mach API](https://github.com/tihmstar/libtakeover)
* [userlandkernel/mach-hook - Hooking mach-o libraries in current or remote processes by patching GOT and NLIST](https://github.com/userlandkernel/mach-hook)

ARM

* [evilsocket/arminject - An application to dynamically inject a shared object into a running process on ARM architectures](https://github.com/evilsocket/arminject)



