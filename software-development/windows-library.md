# Windows library

Uncategorized

* [dra27/opam-experiments - symlinks/symlink.c - 包含一个LsaAddAccountRights()例子](https://github.com/dra27/opam-experiments/blob/master/symlinks/symlink.c)
* [pwn1sher/fltmc - Custom implementation of fltmc.exe command to list minifilter driver and their altitude numbers - C++实现，用FindFilterFirst枚举驱动列表](https://github.com/pwn1sher/fltmc)
* [vvalien/mini_adventure - 包含一个低权限，通过ETW自动开启WebClient服务的代码，2016年就有了](https://github.com/vvalien/mini_adventure)
* [klinix5/WinDefendInjectPoC - 包含ZwCreateUserToken用法示例](https://github.com/klinix5/WinDefendInjectPoC)
* [Winins0/NT782Source - Source for Windows NT build 782](https://github.com/Winins0/NT782Source)
* [gist: system resources physical memory map VM detection trick](https://gist.github.com/CaledoniaProject/4a2b1d81c106e60d4901df927b11d87f)
* [vxunderground/WinAPI-Tricks - Collection of various WINAPI tricks / features used or abused by Malware](https://github.com/vxunderground/WinAPI-Tricks)
* [diversenok/Powercfg - Reversing and reimplementing "powercfg /requests" using Native API](https://github.com/diversenok/Powercfg)
* [Rvn0xsy/BadCode - 恶意代码逃逸源代码](https://github.com/Rvn0xsy/BadCode)
* [EddieIvan01/win32api-practice - Offensive tools written for practice purposes](https://github.com/EddieIvan01/win32api-practice)
* [microsoft/win32metadata - Tooling to generate metadata for Win32 APIs in the Windows SDK - Win32 API 各种 binding，似乎可以代替 pinvoke 了](https://github.com/microsoft/win32metadata)
* [aaaddress1/wow64Jit - Call 32bit NtDLL API directly from WoW64 Layer](https://github.com/aaaddress1/wow64Jit)
* [microsoft/Windows-classic-samples - LSP例子，可以用来做后门](https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Win7Samples/netds/winsock/lsp)
* [yardenshafir/CallbackObjectAnalyzer - Dumps information about all the callback objects found in a dump file and the functions registered for them](https://github.com/yardenshafir/CallbackObjectAnalyzer)
* [gtworek/PSBits - Simple (relatively) things allowing you to dig a bit deeper than usual - 高端工具代码，思路非常多](https://github.com/gtworek/PSBits)
* [zodiacon/WindowsInternals - Windows Internals Book 7th Edition Tools](https://github.com/zodiacon/WindowsInternals)
* [EyeOfRa/WinConMon - Windows Console Monitoring - 能够直接获取cmd.exe的输入输出](https://github.com/EyeOfRa/WinConMon)
* [itm4n/FullPowers - Recover the default privilege set of a LOCAL/NETWORK SERVICE account - 通过创建计划任务，恢复 local service 原有的特权](https://github.com/itm4n/FullPowers)
* [microsoft/WindowsProtocolTestSuites - Windows Protocol Test Suites provide interoperability testing against an implementation of the Windows open specifications - 各种底层协议测试代码，应该会有用处](https://github.com/microsoft/WindowsProtocolTestSuites)
* [DoubleLabyrinth/SecurityDescriptorHelper - SecurityDescriptor Helper - 可以解读 D:P(A;;GA;;;SY) 这样的字符串](https://github.com/DoubleLabyrinth/SecurityDescriptorHelper)
  * https://github.com/p0dalirius/DescribeNTSecurityDescriptor
* [DavidXanatos/wumgr - Windows update managemetn tool for windows 10](https://github.com/DavidXanatos/wumgr)
* [gist: w4kfu/95a87764db7029e03f09d78f7273c4f4 - SHIM 构建和注入，即使 compat 工具不支持；2016开始失效](https://gist.github.com/w4kfu/95a87764db7029e03f09d78f7273c4f4)
* [apriorit/SvcHostDemo - Demo service that runs in svchost.exe](https://github.com/apriorit/SvcHostDemo)
* [itm4n/CDPSvcDllHijacking - 代码的核心价值不是DLL劫持，而是token kidnapping: 遍历4~0xffff编号，尝试复制token，若成功则检查token是否可以利用](https://github.com/itm4n/CDPSvcDllHijacking)
* [outflanknl/Ps-Tools - an advanced process monitoring toolkit for offensive operations](https://github.com/outflanknl/Ps-Tools)
* [blog: Quickpost: Running a Service DLL - 如何使用svchost加载DLL服务](https://blog.didierstevens.com/2019/10/29/quickpost-running-a-service-dll/)
* [stackoverflow: NtCreateToken C++ 例子，未测试](https://stackoverflow.com/questions/47412590/create-a-user-token-from-sid-expand-environment-variables-in-user-context)
* [depletionmode/wsIPC - Working Set Page Cache side-channel IPC PoC](https://github.com/depletionmode/wsIPC)
* [zyantific/zydis - Fast and lightweight x86/x86-64 disassembler library - 持续更新，1.5K star](https://github.com/zyantific/zydis)
* [google/fruit - Fruit, a dependency injection framework for C++](https://github.com/google/fruit)

Cryptography

* [kokke/tiny-AES-c - Small portable AES128/192/256 in C - 3.1K star，ShadowPad后门在用](https://github.com/kokke/tiny-AES-c)

Process tools

* [sensepost/impersonate - A windows token impersonation tool - 没啥亮点，就是常规的token遍历，当用户名匹配后就复制token、创建进程，没有考虑session/high IL的问题](https://github.com/sensepost/impersonate)
* [Win8 之后可以调用 SetProcessMitigationPolicy + ProcessSystemCallDisablePolicy 来禁止直接系统调用](https://github.com/chromium/chromium/blob/99314be8152e688bafbbf9a615536bdbb289ea87/base/win/win_util.cc#L595)
* [SinaKarvandi/Process-Magics - This is a collection of interesting codes about Windows Process creation - Update Sysmon Rules/CriticalProcess/EnumHandles/ImpersonationPipeLine/...](https://github.com/SinaKarvandi/Process-Magics)
* [SekoiaLab/BinaryInjectionMitigation - analysis of the Microsoft binary injection mitigation - 查看进程安全策略，比如禁止加载第三方DLL等等](https://github.com/SekoiaLab/BinaryInjectionMitigation)
* [scorpiosoftware: Parent Process vs. Creator Process - PS_CREATE_NOTIFY_INFO 包含一个 CreatingThreadId 结构，可以判断真实父进程。主要是跟 UpdateProcThreadAttribute 对抗](https://scorpiosoftware.net/2021/01/10/parent-process-vs-creator-process/)
* [pathtofile/PPLRunner - Run Processes as PPL with ELAM - ELAM驱动需要签名，因此这个只是个demo](https://github.com/pathtofile/PPLRunner)
* [blog: Quickpost: SelectMyParent or Playing With the Windows Process Tree - 指定父进程启动，可以降权也可以提权](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/)
  * [decoder-it/psgetsystem - getsystem via parent process using ps1 & embeded c#](https://github.com/decoder-it/psgetsystem)
* [daem0nc0re/TangledWinExec - C# PoCs for investigation of Windows process execution techniques investigation - 伪造cmdline、伪造父进程、进程替换等等](https://github.com/daem0nc0re/TangledWinExec)

Lateral movement

* [diversenok/NtTools - Some random system tools for Windows - 包含一个RunAsS4U代码，有基于SE_TCB权限构造token的代码例子，Delphi实现](https://github.com/diversenok/NtTools)
* [ThunderGunExpress/DCOM_Work - modifies remote registry and when not properly understood could leave a system non-operational](https://github.com/ThunderGunExpress/DCOM_Work)
* [n0thing0x01/session_enum - 通过NetSessionEnum获取域内机器对应用户](https://github.com/n0thing0x01/session_enum)

Network

* [malcomvetter/DnsCache - 使用DNSAPI!DnsGetCacheDataTable获取本机DNS缓存列表](https://github.com/malcomvetter/DnsCache)
* [quarkslab: Guided tour inside WinDefender’s network inspection driver - WFP网络过滤驱动入门](https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html)
* [zodiacon/BITSManager - BITS Transfers Manager](https://github.com/zodiacon/BITSManager)
* [wbenny/mini-tor - proof-of-concept implementation of tor protocol using Microsoft CNG/CryptoAPI - 2019停更](https://github.com/wbenny/mini-tor/)
* [mymmsc/books/Windows网络编程 - 源代码 - NSP例子](https://github.com/mymmsc/books/tree/master/network/Windows%E7%BD%91%E7%BB%9C%E7%BC%96%E7%A8%8B%20-%20%E6%BA%90%E4%BB%A3%E7%A0%81/Chapter14/NSP)
* [ionescu007/hazmat5 - Local OXID Resolver (LCLOR) : Research and Tooling - 原生RPC实现，带OXID接口定义](https://github.com/ionescu007/hazmat5)

Debugging

* [jackullrich/syscall-detect - PoC capable of detecting manual syscalls from usermode - 用PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION来获取syscall调用来源，用dbghelp获取符号，然后检测是否为ntdll等DLL的空间来判断是否合法](https://github.com/jackullrich/syscall-detect)
* [stackoverflow: Reading a .pdb file - 读取PDB的几个方法](https://stackoverflow.com/questions/2040132/reading-a-pdb-file/2040180)

Evasion

* [passthehashbrowns/hiding-your-syscalls - avoiding direct syscall detections](https://github.com/passthehashbrowns/hiding-your-syscalls)
* [LloydLabs/dearg-thread-ipc-stealth - A novel technique to communicate between threads using the standard ETHREAD structure](https://github.com/LloydLabs/dearg-thread-ipc-stealth)
* [93aef0ce4dd141ece6f5/Packer - PoC executable packer using resources](https://github.com/93aef0ce4dd141ece6f5/Packer)
* [icyguider/Shhhloader - SysWhispers Shellcode Loader (Work in Progress)](https://github.com/icyguider/Shhhloader)
* [jthuraisamy/SysWhispers - AV/EDR evasion via direct system calls - python直接生成asm和头文件，只能C++项目用 - 目前defender云端已经被查杀，需要修改asm里的方法名字](https://github.com/jthuraisamy/SysWhispers)
  * [klezVirus/SysWhispers3 - SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls](https://github.com/klezVirus/SysWhispers3)
  * [huaigu4ng/SysWhispers3WinHttp - SysWhispers3WinHttp 基于SysWhispers3项目增添WinHttp分离加载功能并使用32位GCC进行编译，文件大小14KB，可免杀绕过360核晶防护与Defender](https://github.com/huaigu4ng/SysWhispers3WinHttp)
  * [janoglezcampos/c_syscalls - Single stub direct and indirect syscalling with runtime SSN resolving for windows](https://github.com/janoglezcampos/c_syscalls)
* [jthuraisamy/SysWhispers2 - AV/EDR evasion via direct system calls. The usage is almost identical to SysWhispers1 but you don't have to specify which versions of Windows to support - 新版系统里syscall编号并非自增，需要修改](https://github.com/jthuraisamy/SysWhispers2)
  * [mai1zhi2/SysWhispers2_x86 - X86 version of syswhispers2](https://github.com/mai1zhi2/SysWhispers2_x86)
* [hlldz/RefleXXion - RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks, it first collects the syscall numbers of the NtOpenFile, NtCreateSection, NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array](https://github.com/hlldz/RefleXXion)
* [Antimalware Scan Interface Provider for Persistence](https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/)
  * [gist: b4rtik/AmsiProvider.cpp](https://gist.github.com/b4rtik/48ef702603d5e283bc81a05a01fccd40)
* [tttang.com: syscall的前世今生](https://tttang.com/archive/1464/)  

Process

* [BlackOfWorld/NtCreateUserProcess - A small NtCreateUserProcess PoC that spawns a Command prompt](https://github.com/BlackOfWorld/NtCreateUserProcess)
* [Pavel's Blog: How can I close a handle in another process - 使用 NtQueryInformationProcess 获取所有 Handle，使用 DUPLICATE_CLOSE_SOURCE 参数复制 Handle，然后就实现了源的关闭](https://scorpiosoftware.net/2020/03/15/how-can-i-close-a-handle-in-another-process/)
* [xtahi0nix/SetCriticalProcesses - Creating critical processes in Windows](https://github.com/xtahi0nix/SetCriticalProcesses)

Authentication

* [arcadejust/MultiotpCPV2RDP - Credential Provider V2 for Win8 and Win10 with RDP only option](https://github.com/arcadejust/MultiotpCPV2RDP)
* [jas502n/mimikat_ssp - 用RPC调用替代AddSecurityPackage函数，实现DLL加载](https://github.com/jas502n/mimikat_ssp)
* [Dumping Stored Credentials with SeTrustedCredmanAccessPrivilege - 使用CredBackupCredentials函数 + SeTrustedCredmanAccessPrivilege获取任意已登录用户的凭据，没给源码，可以自己写一个](https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html)

Hardening

* [HoShiMin/Avanguard - The Win32 Anti-Intrusion Library - 主要是线程和钩子检查，看起很强](https://github.com/HoShiMin/Avanguard)
* [googleprojectzero: You Won't Believe what this One Line Change Did to the Chrome Sandbox - 加固思路可以参考，JobObject 限制子进程个数为1，Mitigation Policy 禁止子进程创建](https://googleprojectzero.blogspot.com/2020/04/you-wont-believe-what-this-one-line.html)
* [MalwareTech/AppContainerSandbox - An example sandbox using AppContainer (Windows 8+) - StartupInfo里传递安全属性，实现沙箱启动](https://github.com/MalwareTech/AppContainerSandbox)

File system

* [MsF-NTDLL/ChTimeStamp - Changing the Creation time and the Last Written time of a dropped file by the timestamp of other one , like the "kernel32.dll" timestamp](https://github.com/MsF-NTDLL/ChTimeStamp)
* [ORCx41/DeleteShadowCopies - Deleting Shadow Copies In Pure C++ - COM接口实现](https://github.com/ORCx41/DeleteShadowCopies)
* [LloydLabs/delete-self-poc - A way to delete a locked, or current running executable, on disk](https://github.com/LloydLabs/delete-self-poc)
* [gist: C++: Create/Open/Attach/Detach VHD (draft) - Win10以上可用，支持ISO](https://gist.github.com/alexpahom/ae7dfe7bac48229aaf80c80a9cafab89)
  * [Weaponizing Windows Virtualization](https://vxug.fakedoma.in/papers/VXUG/Exclusive/WeaponizingWindowsVirtualization.pdf)
* [Real-time file monitoring on Windows with osquery - Windows 文件监控三种方案: ReadDirectoryChangesW 缓冲区大小固定，事件丢失多；内核驱动容易崩溃；NTFS journal 最可靠，osquery 就是这样做的](https://blog.trailofbits.com/2020/03/16/real-time-file-monitoring-on-windows-with-osquery/)
* [ultraembedded/fat_io_lib - Small footprint, low dependency, C code implementation of a FAT16 & FAT32 driver - FAT读写库，可以是基于文件的磁盘系统，ComRAT4在用](https://github.com/ultraembedded/fat_io_lib)
* [NtRaiseHardError/Anti-Delete - Protects deletion of files with a specified extension using a kernel-mode driver](https://github.com/NtRaiseHardError/Anti-Delete)

Registry

* [panagioto/SyscallHide - Create a Run registry key with direct system calls. Inspired by @Cneelis's Dumpert and SharpHide - 过不了sysmon](https://github.com/panagioto/SyscallHide)
* [3gstudent/HiddenNtRegistry - 以 `\0` 开头的注册表键值，无法用 Win32 API 打开，必须用 NT API](https://github.com/3gstudent/HiddenNtRegistry)
  * https://github.com/outflanknl/SharpHide
  * https://github.com/ewhitehats/InvisiblePersistence

Desktop

* [AgigoNoTana/HiddenDesktopViewer - This tool reveals hidden desktops and investigate processes/threads utilizing hidden desktops - 用EnumDesktops等API枚举隐藏桌面](https://github.com/AgigoNoTana/HiddenDesktopViewer)
* [byp455/CanYouCTheThief - A C implementation of the Sektor7 "A Thief" Windows privesc technique - CredUIPromptForCredentials本地钓鱼示例](https://github.com/byp455/CanYouCTheThief)
* [KANKOSHEV/NoScreen - Hiding the window from screenshots using the function win32kfull::ChangeWindowTreeProtection - 似乎是防止截屏的](https://github.com/KANKOSHEV/NoScreen)
* [rprichard/winpty - A Windows software package providing an interface similar to a Unix pty-master for communicating with Windows console programs - 1.1K star](https://github.com/rprichard/winpty)
* [vmcall/dxgkrnl_hook - C++ graphics kernel subsystem hook](https://github.com/vmcall/dxgkrnl_hook)
* [google/gumbo-parser - An HTML5 parsing library in pure C99 - 2016停更](https://github.com/google/gumbo-parser)
* [libyal/liblnk - Library and tools to access the Windows Shortcut File (LNK) format](https://github.com/libyal/liblnk)

Memory

* [0vercl0k/sic - Enumerate user mode shared memory mappings on Windows](https://github.com/0vercl0k/sic)
* [DarthTon/Blackbone - Windows memory hacking library - 文档少，直接看例子](https://github.com/DarthTon/Blackbone)
* [joe-desimone/patriot - Small research project for detecting various kinds of in-memory stealth techniques - 新玩具，误报率未知](https://github.com/joe-desimone/patriot)

GetProcAddress

* [arbiter34/GetProcAddress - Recreation of GetProcAddress without external dependencies on Windows Libraries](https://github.com/arbiter34/GetProcAddress)
* [WKL-Sec/FuncAddressPro - A stealthy, assembly-based tool for secure function address resolution, offering a robust alternative to GetProcAddress - 基于EAT扫描，汇编实现，兼容性未知](https://github.com/WKL-Sec/FuncAddressPro)
* [MzHmO/SymProcAddress - Zero EAT touch way to retrieve function addresses (GetProcAddress on steroids) - 基于DbgHelp.dll实现函数定位](https://github.com/MzHmO/SymProcAddress)

Memory loading

* [TheD1rkMtr/FilelessPELoader - Loading Remote AES Encrypted PE in memory , Decrypted it and run it](https://github.com/TheD1rkMtr/FilelessPELoader)
* [nettitude/RunPE - C# Reflective loader for unmanaged binaries](https://github.com/nettitude/RunPE)
* [frkngksl/Huan - an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently, it works on 64 bit PE files](https://github.com/frkngksl/Huan)
* [tishion/mmLoader - A library for loading dll module bypassing windows PE loader from memory (x86/x64)](https://github.com/tishion/mmLoader)
* [kleiton0x00/Proxy-DLL-Loads - A proof of concept demonstrating the DLL-load proxying using undocumented Syscalls - 这个不是内存加载，基于TpAllocTimer做的加载，非公开的机制](https://github.com/kleiton0x00/Proxy-DLL-Loads)
* [bats3c/DarkLoadLibrary - LoadLibrary for offensive operations - 手动加载DLL，绕过内核ImageLoadCallbackRoutine监控](https://github.com/bats3c/DarkLoadLibrary)
* [fancycode/MemoryModule - 内存DLL加载，非常稳定 - MemoryLoadLibrary()/MemoryLoadLibraryEx()](https://github.com/fancycode/MemoryModule)
  * [scythe-io/memory-module-loader - Updated by Ateeq Sharfuddin to support TLS; Updated by Jonathan Lim to support AMD64](https://github.com/scythe-io/memory-module-loader)
  * [strivexjun/MemoryModulePP - modify from memorymodule. support exception](https://github.com/strivexjun/MemoryModulePP)
* [86hh/DreamLoader - Simple 32/64-bit PEs loader](https://github.com/86hh/DreamLoader)
* [zeroSteiner/reflective-polymorphism - provides various utilities for the self-modification of PE images](https://github.com/zeroSteiner/reflective-polymorphism)
* [rasta-mouse/TikiTorch - Process Hollowing via DotNetToJScript](https://github.com/rasta-mouse/TikiTorch)
* [kernelm0de/RunPE-ProcessHollowing - Process Hollowing is a technique mainly used by Malware Creators to hide malicious code behind Legitimate Process](https://github.com/kernelm0de/RunPE-ProcessHollowing)
* [m0n0ph1/Process-Hollowing - Great explanation of Process Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
* [aaaddress1/RunPE-In-Memory - Run a 32bit copy of Exe File in memory (like what Software Packer Do)](https://github.com/aaaddress1/RunPE-In-Memory)
* [Zer0Mem0ry/RunPE - Code that allows running another windows PE in the same address space as the host process](https://github.com/Zer0Mem0ry/RunPE)
* [nettitude/SimplePELoader - A very simple PE loader for loading DLL's into memory without using LoadLibrary](https://github.com/nettitude/SimplePELoader)

UWP

* [zodiacon/RunAppContainer - Run executables in an AppContainer - 通过白名单权限方式，在UWP下面执行命令](https://github.com/zodiacon/RunAppContainer)

Printer

* [uri247/wdk81 - Print Monitors Samples](https://github.com/uri247/wdk81/tree/master/Print%20Monitors%20Samples/C%2B%2B/localmon)

签名工具

* [med0x2e/SigFlip - a tool for patching authenticode signed PE files (exe, dll, sys ..etc) without invalidating or breaking the existing signature - 纯鸡肋工具](https://github.com/med0x2e/SigFlip)
* [trailofbits/uthenticode - A cross-platform library for verifying Authenticode signatures - WinVerifyTrust/CertVerifyCertificateChainPolicy 跨平台实现](https://github.com/trailofbits/uthenticode)
* [mattifestation/PoCSubjectInterfacePackage - A proof-of-concept subject interface package (SIP) used to demonstrate digital signature subversion attacks - WINTRUST PE 签名校验的样例](https://github.com/mattifestation/PoCSubjectInterfacePackage)
  * [SpectorOps: Subverting Trust in Windows](https://www.specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)

Cheat

* [niemand-sec/AntiCheat-Testing-Framework - Framework to test any Anti-Cheat](https://github.com/niemand-sec/AntiCheat-Testing-Framework)

# Resources

* [horsicq/xntsv - detailed viewing of system structures for Windows](https://github.com/horsicq/xntsv)
* [ionescu007/clfs-docs - Unofficial Common Log File System (CLFS) Documentation](https://github.com/ionescu007/clfs-docs/)
* [Windows Debugger API — The End of Versioned Structures](https://www.driverentry.com/articles/94)
* [How to secure a Windows RPC Server, and how not to - RPC认证介绍，包含EFSRPC的认证方式和Windows修复方法](https://www.tiraniddo.dev/2021/08/how-to-secure-windows-rpc-server-and.html)
* [Understanding Network Access in Windows AppContainers](https://googleprojectzero.blogspot.com/2021/08/understanding-network-access-windows-app.html)
* [The new Component Filter mitigation - 一个新的加固机制PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER，对目标进程开启后将无法调用ntfs的7个API](https://big5-sec.github.io/posts/component-filter-mitigation/)

# Best practices

* [Shlwapi!PathCombineW(dest, dir, filename) 最多写入260个字母，因此调用之前需要先检查长度](https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathcombinew)
