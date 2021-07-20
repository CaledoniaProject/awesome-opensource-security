# CobaltStrike addons

A collection of cobaltstrike addons

## Collections

3rd-party lists

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

* https://github.com/ORCA666/Cobalt-Wipe
* https://github.com/RASSec/Cobalt-Strike
* [Freakboy/CobaltStrike - CobaltStrike's source code](https://github.com/Freakboy/CobaltStrike)
* [ca3tie1/CrackSleeve - 破解CS4.0](https://github.com/ca3tie1/CrackSleeve)
* [Yang0615777/SecondaryDevCobaltStrike - 二次开发过后的CobaltStrike,版本为4.1.在原来CobaltStrike的基础上修改多处特征,解决流量查杀问题](https://github.com/Yang0615777/SecondaryDevCobaltStrike)

Exploits

* [vysec/CVE-2018-4878](https://github.com/vysec/CVE-2018-4878)

Detection Evasion

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

* [rsmudge/ElevateKit - demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload](https://github.com/rsmudge/ElevateKit)
* [rxwx/spoolsystem - a CNA script for Cobalt Strike which uses @itm4n's Print Spooler named pipe impersonation trick to gain SYSTEM privileges without creating any new process or relying on cross-process shellcode injection](https://github.com/rxwx/spoolsystem)
* [realoriginal/bof-NetworkServiceEscalate - Abuses the Shared Logon Session ID Issue by the awesome James Forshaw To Achieve System From NetworkService. Can be used as a "getsystem" as well](https://github.com/realoriginal/bof-NetworkServiceEscalate)
  * [Sharing a Logon Session a Little Too Much - NetworkService通过管道提权到SYSTEM问题说明](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)

Post Exploitation

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

* [ZonkSec/persistence-aggressor-script](https://github.com/ZonkSec/persistence-aggressor-script)
* [connormcgarr/cThreadHijack - Beacon Object File (BOF) for remote process injection via thread hijacking](https://github.com/connormcgarr/cThreadHijack)
* [0xthirteen/StayKit - Cobalt Strike kit for Persistence](https://github.com/0xthirteen/StayKit)

Profiles

* [rsmudge/Malleable-C2-Profiles - Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use](https://github.com/rsmudge/Malleable-C2-Profiles)
* [bluscreenofjeff/Malleable-C2-Randomizer - A script to randomize Cobalt Strike Malleable C2 profiles and reduce the chances of flagging signature-based detection controls](https://github.com/bluscreenofjeff/Malleable-C2-Randomizer)
* [threatexpress/malleable-c2 - Cobalt Strike Malleable C2 Design and Reference Guide - 效率低下](https://github.com/threatexpress/malleable-c2)
* [Porchetta-Industries/pyMalleableC2 - Python interpreter for Cobalt Strike Malleable C2 Profiles. Allows you to parse, build and modify them programmatically](https://github.com/Porchetta-Industries/pyMalleableC2)

Detection

* [3lp4tr0n/BeaconHunter - Detect and respond to Cobalt Strike beacons using ETW](https://github.com/3lp4tr0n/BeaconHunter)
* [vysec/CobaltSplunk - Splunk Dashboard for CobaltStrike logs](https://github.com/vysec/CobaltSplunk)
* [nccgroup/pybeacon - A collection of scripts for dealing with Cobalt Strike beacons in Python](https://github.com/nccgroup/pybeacon)
* [mdsec: Detecting and Advancing In-Memory .NET Tradecraft - execute-assembly 会保留PE头信息，可以识别到](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/)
* [Apr4h/CobaltStrikeScan - Scan files or process memory for CobaltStrike beacons and parse their configuration](https://github.com/Apr4h/CobaltStrikeScan)
* [slaeryan/DetectCobaltStomp - Detects Module Stomping as implemented by Cobalt Strike - 检查LDR_DATA_TABLE_ENTRY.ImageDll是否设置，如果未设置则判定为EXE注入](https://github.com/slaeryan/DetectCobaltStomp)
* [MichaelKoczwara/Awesome-CobaltStrike-Defence - Defences against Cobalt Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)

Uncategorized

* [0xpat/COFFInjector - PoC MSVC COFF Object file loader/injector](https://github.com/0xpat/COFFInjector)
* [mstxq17/FrpProPlugin - frp0.33修改版,过流量检测,免杀,支持加载远程配置文件可用于cs直接使用的插件](https://github.com/mstxq17/FrpProPlugin)
* [trustedsec/COFFLoader - a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it](https://github.com/trustedsec/COFFLoader)
* [gist: A POC showing how to modify Cobalt Strike beacon at runtime](https://gist.github.com/xpn/6c40d620607e97c2a09c70032d32d278)
* [SecIdiot/Beacon - Open Source Cobalt Strike Beacon. In-development stage](https://github.com/SecIdiot/Beacon)
* [MichaelKoczwara/Awesome-CobaltStrike-Defence - Defences against Cobalt Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [rsmudge/ElevateKit - The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload](https://github.com/rsmudge/ElevateKit)
* [Sentinel-One/CobaltStrikeParser - Python parser for CobaltStrike Beacon's configuration](https://github.com/Sentinel-One/CobaltStrikeParser)
* [pandasec888/taowu-cobalt-strike](https://github.com/pandasec888/taowu-cobalt-strike)
* [EncodeGroup/AggressiveProxy - Project to enumerate proxy configurations and generate shellcode from CobaltStrike](https://github.com/EncodeGroup/AggressiveProxy)
* [rsmudge/ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
* [trustedsec/CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
* [rvrsh3ll/BOF_Collection - Various Cobalt Strike BOFs](https://github.com/rvrsh3ll/BOF_Collection)
* [m0ngo0se/Peinject_dll](https://github.com/m0ngo0se/Peinject_dll)
* [josephkingstone/cobalt_strike_extension_kit](https://github.com/josephkingstone/cobalt_strike_extension_kit)
* [fox-it/LDAPFragger - a Command and Control tool that enables attackers to route Cobalt Strike beacon data over LDAP using user attributes](https://github.com/fox-it/LDAPFragger)
* [QAX-A-Team/CobaltStrike-Toolset - Aggressor Script, Kits, Malleable C2 Profiles, External C2 and so on](https://github.com/QAX-A-Team/CobaltStrike-Toolset)
* [Ch1ngg/AggressorScript-UploadAndRunFrp - AggressorScript-UploadAndRunFrp/上传frpc并且运行frpc](https://github.com/Ch1ngg/AggressorScript-UploadAndRunFrp)
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




