3rd-party lists

* [mgeeky/cobalt-arsenal - My collection of battle-tested Aggressor Scripts for Cobalt Strike 4.0+](https://github.com/mgeeky/cobalt-arsenal)
* [pwn1sher/CS-BOFs](https://github.com/pwn1sher/CS-BOFs)
* [vysec/Aggressor-VYSEC](https://github.com/vysec/Aggressor-VYSEC)
* [harleyQu1nn/AggressorScripts - Collection of Aggressor scripts for Cobalt Strike 3.0+ pulled from multiple sources](https://github.com/harleyQu1nn/AggressorScripts)
* [killswitch-GUI/CobaltStrike-ToolKit - Some useful scripts for CobaltStrike](https://github.com/killswitch-GUI/CobaltStrike-ToolKit)
* [invokethreatguy/CSASC - Cobalt Strike Aggressor Script Collection](https://github.com/invokethreatguy/CSASC)
* [RhinoSecurityLabs/Aggressor-Scripts - Aggregation of Cobalt Strike's aggressor scripts](https://github.com/RhinoSecurityLabs/Aggressor-Scripts)
* [offsecginger/AggressorScripts - Various Aggressor Scripts I've Created](https://github.com/offsecginger/AggressorScripts)
* [Cliov/Arsenal - Cobalt Strike 3.13 Arsenal Kit](https://github.com/Cliov/Arsenal)
* [zer0yu/Awesome-CobaltStrike - cobaltstrike的相关资源汇总](https://github.com/zer0yu/Awesome-CobaltStrike)
* [S1ckB0y1337/Cobalt-Strike-CheatSheet - Some notes and examples for cobalt strike's functionality](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)

Binary releases

* [ca3tie1/CrackSleeve - 破解CS4.0](https://github.com/ca3tie1/CrackSleeve)
* https://verify.cobaltstrike.com
* [Twi1ight/CSAgent - 采用javaagent+javassist的方式动态修改jar包，可直接加载原版cobaltstrike.jar，理论上支持到目前为止的所有4.x版本](https://github.com/Twi1ight/CSAgent)
* [Like0x/0xagent - CobaltStrike 4.0 - 4.5 Patch](https://github.com/Like0x/0xagent)

Filesystem

* [Octoberfest7/MemFiles - A CobaltStrike toolkit to write files produced by Beacon to memory instead of disk - MDE会根据落地的dump文件查杀lsass dump行为，通过写入内存盘可以绕过检测](https://github.com/Octoberfest7/MemFiles)

Analysis

* https://github.com/avast/ioc/tree/master/CobaltStrike/api_hashes
* [brett-fitz/pyMalleableProfileParser - Parses Cobalt Strike malleable C2 profiles](https://github.com/brett-fitz/pyMalleableProfileParser)
* [Sentinel-One/CobaltStrikeParser - Python parser for CobaltStrike Beacon's configuration - 只能处理stageless beacon](https://github.com/Sentinel-One/CobaltStrikeParser)
* [fox-it/dissect.cobaltstrike - Python library for dissecting and parsing Cobalt Strike related data such as Beacon payloads and Malleable C2 Profiles](https://github.com/fox-it/dissect.cobaltstrike)

Exploits

* [0xjiefeng/CVE-2024-35250-BOF - Cobalt Strike 的 CVE-2024-35250 的 BOF](https://github.com/0xjiefeng/CVE-2024-35250-BOF)
* [vysec/CVE-2018-4878](https://github.com/vysec/CVE-2018-4878)
* [icyguider/UAC-BOF-Bonanza - Collection of UAC Bypass Techniques Weaponized as BOFs](https://github.com/icyguider/UAC-BOF-Bonanza)

Detection Evasion

* [EvilGreys/Cobalt-Strike-Profiles-for-EDR-Evasion - Cobalt Strike Profiles for EDR Evasion](https://github.com/EvilGreys/Cobalt-Strike-Profiles-for-EDR-Evasion)
* [Workingdaturah/Payload-Generator - An aggressor script that can help automate payload building in Cobalt Strike](https://github.com/Workingdaturah/Payload-Generator)
* [ASkyeye/PoolPartyBof - A beacon object file implementation of PoolParty Process Injection Technique](https://github.com/ASkyeye/PoolPartyBof)
* [Octoberfest7/Inline-Execute-PE - Execute unmanaged Windows executables in CobaltStrike Beacons - 作者强调仅限mingw程序](https://github.com/Octoberfest7/Inline-Execute-PE)
  * [fortra/No-Consolation - A BOF that runs unmanaged PEs inline - 上面那个在创建console的时候会启动一个conhost.exe，这个不会，具体参考他的博客](https://github.com/fortra/No-Consolation)
* [EspressoCake/Defender_Exclusions-BOF - A BOF to determine Windows Defender exclusions](https://github.com/EspressoCake/Defender_Exclusions-BOF)
  * [EspressoCake/Defender-Exclusions-Creator-BOF - A BOF to add or remove Windows Defender exclusions](https://github.com/EspressoCake/Defender-Exclusions-Creator-BOF)
* [H4de5-7/geacon_pro - 跨平台重构了Cobaltstrike Beacon，适配了大部分Beacon的功能，行为对国内主流杀软免杀，支持4.1以上的版本。 A cobaltstrike Beacon bypass anti-virus, supports 4.1+ version](https://github.com/H4de5-7/geacon_pro)
* [kyleavery/AceLdr - Cobalt Strike UDRL for memory scanner evasion](https://github.com/kyleavery/AceLdr)
* [airbus-cert/Invoke-Bof - Load any Beacon Object File using Powershell - 手动解析BOF格式，解析Win32 API地址，然后加载，非常高级](https://github.com/airbus-cert/Invoke-Bof)
* [helpsystems/nanodump - Dumping LSASS has never been so stealthy - 手动读取内存，并按照minidump结构体格式生成文件；支持十几种方式，包括最新的shtinkering werfault方式](https://github.com/helpsystems/nanodump)
* [darkr4y/geacon - Practice Go programming and implement CobaltStrike's Beacon in Go](https://github.com/darkr4y/geacon)
* [SecIdiot/TitanLdr - A crappy Reflective Loader written in C and assembly for Cobalt Strike. Redirects DNS Beacon over DoH](https://github.com/SecIdiot/TitanLdr)
* [boku7/CobaltStrikeReflectiveLoader - Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities - 稳定性存疑](https://github.com/boku7/CobaltStrikeReflectiveLoader)
* [boku7/injectAmsiBypass - Bypass AMSI in a remote process with code injection](https://github.com/boku7/injectAmsiBypass)
* [mgeeky/RedWarden - Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation](https://github.com/mgeeky/RedWarden)
* [anthemtotheego/CredBandit - uses static x64 syscalls to perform a complete in memory dump of a process. The memory dump is done by using NTFS transactions which allows us to write the dump to memory and the MiniDumpWriteDump API has been replaced with an adaptation of ReactOS's implementation of MiniDumpWriteDump](https://github.com/anthemtotheego/CredBandit)
* [rsmudge/unhook-bof - Remove API hooks from a Beacon process](https://github.com/rsmudge/unhook-bof)
  * [riccardo.ancarani94/ntdll-refresher-hook-removal-bof - A Beacon Object File used to remove userland hooks from NTDLL. Currently supports only 64 bit (although the change is trivial)](https://gitlab.com/riccardo.ancarani94/ntdll-refresher-hook-removal-bof)
* [EncodeGroup/BOF-RegSave - Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File](https://github.com/EncodeGroup/BOF-RegSave)
* [outflanknl/FindObjects-BOF - A Cobalt Strike Beacon Object File (BOF) project which uses direct system calls to enumerate processes for specific loaded modules or process handles](https://github.com/outflanknl/FindObjects-BOF)
* [ajpc500/BOFs - Collection of Beacon Object Files](https://github.com/ajpc500/BOFs)
* [outflanknl/InlineWhispers - Direct System Calls for Beacon Object Files (BOF)](https://github.com/outflanknl/InlineWhispers)
  * [outflanknl/WdToggle - A Cobaltstrike Beacon Object file which uses direct system calls to enable WDigest credential caching - 直接修改lsass内存，来开启WDigest的值，内存offset是写死的](https://github.com/outflanknl/WdToggle)
* [SecIdiot/CobaltPatch - Cobalt Strike Malleable Profile Inline Patch Template: A Position Independent Code (PIC) Code Template For Creating Shellcode That Can Be Appended In Stage / Post-Ex Blocks. Made for C Programmers](https://github.com/SecIdiot/CobaltPatch)
* [ThunderGunExpress/Reflective_PSExec - Customized PSExec via Reflective DLL](https://github.com/ThunderGunExpress/Reflective_PSExec)
* [Mr-Un1k0d3r/SCT-obfuscator - Cobalt Strike SCT payload obfuscator](https://github.com/Mr-Un1k0d3r/SCT-obfuscator)
* [cube0x0/SharpeningCobaltStrike - in realtime v35/40 dotnet compiler for your linux Cobalt Strike C2. New fresh compiled and obfuscated binary for each use](https://github.com/cube0x0/SharpeningCobaltStrike)
* [tomcarver16/BOF-DLL-Inject - a custom Beacon Object File that uses manual map DLL injection in order to migrate a dll into a process all from memory](https://github.com/tomcarver16/BOF-DLL-Inject)
* [seebug: Cobalt Strike 绕过流量审计](https://paper.seebug.org/1349/)

Privilege escalation

* [mstxq17/CVE-2021-1675_RDL_LPE - PrintNightMare LPE提权漏洞的CS 反射加载插件。开箱即用、通过内存加载、混淆加载的驱动名称来ByPass Defender/EDR](https://github.com/mstxq17/CVE-2021-1675_RDL_LPE)
* [rsmudge/ElevateKit - demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload](https://github.com/rsmudge/ElevateKit)
* [rxwx/spoolsystem - a CNA script for Cobalt Strike which uses @itm4n's Print Spooler named pipe impersonation trick to gain SYSTEM privileges without creating any new process or relying on cross-process shellcode injection](https://github.com/rxwx/spoolsystem)
* [realoriginal/bof-NetworkServiceEscalate - Abuses the Shared Logon Session ID Issue by the awesome James Forshaw To Achieve System From NetworkService. Can be used as a "getsystem" as well](https://github.com/realoriginal/bof-NetworkServiceEscalate)
  * [Sharing a Logon Session a Little Too Much - NetworkService通过管道提权到SYSTEM问题说明](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)

Post Exploitation

* [DeEpinGh0st/Erebus - CobaltStrike后渗透测试插件 - 2021停更](https://github.com/DeEpinGh0st/Erebus)
* [WKL-Sec/HiddenDesktop - Hidden Desktop (often referred to as HVNC) is a tool that allows operators to interact with a remote desktop session without the user knowing - 反弹VNC，需要先监听端口](https://github.com/WKL-Sec/HiddenDesktop)
* [netero1010/RDPHijack-BOF - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking](https://github.com/netero1010/RDPHijack-BOF)
* [kyleavery/inject-assembly - Inject .NET assemblies into an existing process](https://github.com/kyleavery/inject-assembly)
* [xforcered/xPipe - Cobalt Strike BOF to list Windows Pipes & return their Owners & DACL Permissions](https://github.com/xforcered/xPipe)
* [EspressoCake/Firewall_Walker_BOF - A BOF to interact with COM objects associated with the Windows software firewall](https://github.com/EspressoCake/Firewall_Walker_BOF)
* [CCob/BOF.NET - A .NET Runtime for Cobalt Strike's Beacon Object Files](https://github.com/CCob/BOF.NET)
* [xforcered/InlineExecute-Assembly - perform in process .NET assembly execution](https://github.com/xforcered/InlineExecute-Assembly)
* [hlldz/Phant0m - Windows Event Log Killer](https://github.com/hlldz/Phant0m)
* [sec-consult/aggrokatz - enables pypykatz to interface with the beacons remotely and allows it to parse LSASS dump files and registry hive files to extract credentials and other secrets stored without downloading the file and without uploading any suspicious code to the beacon](https://github.com/sec-consult/aggrokatz)
* [jsecu/CredManBOF - dumping the credential manager by abusing the SeTrustedCredmanAccess Privilege](https://github.com/jsecu/CredManBOF)
* [jnqpblc/SharpTask - a simple code set to interact with the Task Scheduler service api and is compatible with Cobalt Strike](https://github.com/jnqpblc/SharpTask)
* [josephkingstone/cobalt_strike_extension_kit - Tired of typing execute-assembly everytime you use Cobalt Strike? Clone this.](https://github.com/josephkingstone/cobalt_strike_extension_kit)
* [Skactor/tvnjviewer4cs - TightVNC library for building Cobalt Strike - java写的](https://github.com/Skactor/tvnjviewer4cs)
* [bats3c/ChromeTools - A collection of tools to abuse chrome browser - Hook WriteFile获取IPC内容，比如SSL解密后的内容](https://github.com/bats3c/ChromeTools)

Persistence

* [IcebreakerSecurity/PersistBOF - A tool to help automate common persistence mechanisms](https://github.com/IcebreakerSecurity/PersistBOF)
* [ZonkSec/persistence-aggressor-script](https://github.com/ZonkSec/persistence-aggressor-script)
* [connormcgarr/cThreadHijack - Beacon Object File (BOF) for remote process injection via thread hijacking](https://github.com/connormcgarr/cThreadHijack)
* [0xthirteen/StayKit - Cobalt Strike kit for Persistence](https://github.com/0xthirteen/StayKit)

Profiles

* [Tylous/SourcePoint - a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion](https://github.com/Tylous/SourcePoint)
* [rsmudge/Malleable-C2-Profiles - Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use](https://github.com/rsmudge/Malleable-C2-Profiles)
* [bluscreenofjeff/Malleable-C2-Randomizer - A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls](https://github.com/bluscreenofjeff/Malleable-C2-Randomizer)
* [threatexpress/malleable-c2 - Cobalt Strike Malleable C2 Design and Reference Guide - 效率低下](https://github.com/threatexpress/malleable-c2)
* [Porchetta-Industries/pyMalleableC2 - Python interpreter for Cobalt Strike Malleable C2 Profiles. Allows you to parse, build and modify them programmatically](https://github.com/Porchetta-Industries/pyMalleableC2)

Detection

* [thefLink/Hunt-Sleeping-Beacons - Aims to identify sleeping beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons)
* [cs-decrypt-metadata.py - didier steven开发，在SSL解密后，可以解析CS通信数据](https://blog.didierstevens.com/2021/11/12/update-cs-decrypt-metadata-py-version-0-0-2/)
* [1768.py - didier steven开发，用来分析CS beacon，并检查是否为已知的License ID或者cert](https://blog.didierstevens.com/2021/11/21/update-1768-py-version-0-0-10/)
* [CCob/BeaconEye - Hunts out CobaltStrike beacons and logs operator command output](https://github.com/CCob/BeaconEye)
* [RomanEmelyanov/CobaltStrikeForensic - Toolset for research malware and Cobalt Strike beacons](https://github.com/RomanEmelyanov/CobaltStrikeForensic)
* [huoji120/CobaltStrikeDetected - 40行代码检测到大部分CobaltStrike的shellcode - 方法是通用的，不清楚是否会误报](https://github.com/huoji120/CobaltStrikeDetected)
* [3lp4tr0n/BeaconHunter - Detect and respond to Cobalt Strike beacons using ETW](https://github.com/3lp4tr0n/BeaconHunter)
* [vysec/CobaltSplunk - Splunk Dashboard for CobaltStrike logs](https://github.com/vysec/CobaltSplunk)
* [nccgroup/pybeacon - A collection of scripts for dealing with Cobalt Strike beacons in Python](https://github.com/nccgroup/pybeacon)
* [mdsec: Detecting and Advancing In-Memory .NET Tradecraft - execute-assembly 会保留PE头信息，可以识别到](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/)
* [Apr4h/CobaltStrikeScan - Scan files or process memory for CobaltStrike beacons and parse their configuration - 核心技术是获取注入线程，修改已有SEC_IMAGE标志的内存块即可绕过](https://github.com/Apr4h/CobaltStrikeScan)
* [slaeryan/DetectCobaltStomp - Detects Module Stomping as implemented by Cobalt Strike - 检查LDR_DATA_TABLE_ENTRY.ImageDll是否设置，如果未设置则判定为EXE注入](https://github.com/slaeryan/DetectCobaltStomp)
* [MichaelKoczwara/Awesome-CobaltStrike-Defence - Defences against Cobalt Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)

Lateral movements

* [mez-0/winrmdll - C++ WinRM API via Reflective DLL](https://github.com/mez-0/winrmdll)
* [mstxq17/FrpProPlugin - frp0.33修改版,过流量检测,免杀,支持加载远程配置文件可用于cs直接使用的插件](https://github.com/mstxq17/FrpProPlugin)
* [rsmudge/ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
* [Ch1ngg/AggressorScript-UploadAndRunFrp - AggressorScript-UploadAndRunFrp/上传frpc并且运行frpc](https://github.com/Ch1ngg/AggressorScript-UploadAndRunFrp)

Hardening

* [lovechoudoufu/GoogleCSAgent_cdf - CSAgent 与 GoogleAuth 的缝合体，cobalt strike4.4版本的破解+otp动态口令的agent](https://github.com/lovechoudoufu/GoogleCSAgent_cdf)

Uncategorized

* [med0x2e/ExecuteAssembly - Load/Inject .NET assemblies by; reusing the host (spawnto) process loaded CLR AppDomainManager, Stomping Loader/.NET assembly PE DOS headers, Unlinking .NET related modules, bypassing ETW+AMSI, avoiding EDR hooks via NT static syscalls (x64) and hiding imports by dynamically resolving APIs (hash)](https://github.com/med0x2e/ExecuteAssembly/)
* [boku7/BokuLoader - Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities](https://github.com/boku7/BokuLoader)
  * https://github.com/xforcered/BokuLoader
* [fox-it/cobaltstrike-beacon-data - Open Dataset of Cobalt Strike Beacon metadata (2018-2022)](https://github.com/fox-it/cobaltstrike-beacon-data)
* [nettitude/RunOF - A tool to run object files, mainly beacon object files (BOF), in .Net](https://github.com/nettitude/RunOF)
* [FalconForceTeam/BOF2shellcode - POC tool to convert CobaltStrike BOF files to raw shellcode](https://github.com/FalconForceTeam/BOF2shellcode)
* [0xpat/COFFInjector - PoC MSVC COFF Object file loader/injector](https://github.com/0xpat/COFFInjector)
* [trustedsec/COFFLoader - a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it](https://github.com/trustedsec/COFFLoader)
* [gist: A POC showing how to modify Cobalt Strike beacon at runtime](https://gist.github.com/xpn/6c40d620607e97c2a09c70032d32d278)
* [pandasec888/taowu-cobalt-strike](https://github.com/pandasec888/taowu-cobalt-strike)
* [EncodeGroup/AggressiveProxy - Project to enumerate proxy configurations and generate shellcode from CobaltStrike](https://github.com/EncodeGroup/AggressiveProxy)
* [trustedsec/CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
* [rvrsh3ll/BOF_Collection - Various Cobalt Strike BOFs](https://github.com/rvrsh3ll/BOF_Collection)
* [m0ngo0se/Peinject_dll](https://github.com/m0ngo0se/Peinject_dll)
* [fox-it/LDAPFragger - a Command and Control tool that enables attackers to route Cobalt Strike beacon data over LDAP using user attributes](https://github.com/fox-it/LDAPFragger)
* [QAX-A-Team/CobaltStrike-Toolset - Aggressor Script, Kits, Malleable C2 Profiles, External C2 and so on](https://github.com/QAX-A-Team/CobaltStrike-Toolset)
* [SpiderLabs/SharpCompile - an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime](https://github.com/SpiderLabs/SharpCompile)
* [vysec/MorphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/MorphHTA)
* [threatexpress/cs2modrewrite - Convert Cobalt Strike profiles to modrewrite scripts](https://github.com/threatexpress/cs2modrewrite)
* [FortyNorthSecurity/AggressorAssessor - Aggressor scripts for phases of a pen test or red team assessment](https://github.com/FortyNorthSecurity/AggressorAssessor)
* [Truneski/external_c2_framework - Python api for usage with cobalt strike's External C2 specification](https://github.com/Truneski/external_c2_framework)
* [gist: SharpGen Aggressor Beacon Wrapper](https://gist.github.com/dtmsecurity/051cd24658ec22e6e916047936578a27)
* [ryhanson/ExternalC2 - A library for integrating communication channels with the Cobalt Strike External C2 server](https://github.com/ryhanson/ExternalC2)
* [gloxec/CrossC2 - generate CobaltStrike's cross-platform payload](https://github.com/gloxec/CrossC2)
* [mdsecactivebreach/RDPInception - A proof of concept for the RDP Inception Attack](https://github.com/mdsecactivebreach/RDPInception)
* [mdsecactivebreach/Browser-ExternalC2 - External C2 Using IE COM Objects](https://github.com/mdsecactivebreach/Browser-ExternalC2)
  * [External C2, IE COM Objects and how to use them for Command and Control](https://www.mdsec.co.uk/2019/02/external-c2-ie-com-objects-and-how-to-use-them-for-command-and-control/)

## Tutorials

* [Exploring Cobalt Strike's ExternalC2 framework](https://blog.xpnsec.com/exploring-cobalt-strikes-externalc2-framework/)
