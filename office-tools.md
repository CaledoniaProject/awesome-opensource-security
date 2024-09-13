## Collections

Add-ins

* [vivami/OutlookParasite - Outlook persistence using VSTO add-ins- VTSO插件例子，包含一个powershell安装脚本，安装仅需要改注册表](https://github.com/vivami/OutlookParasite)
* [S4R1N/BadOutlook - Malicious Outlook Reader](https://github.com/S4R1N/BadOutlook)
* [f-secure: Add-In Opportunities for Office Persistence - Word/Excel可以加载特定目录的DLL插件，Excel/PPT可以加载特定目录的VBA模块，其他类型的插件有COM/VBE组件](https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/)
  * [3gstudent/Office-Persistence - Use powershell to test Office-based persistence methods](https://github.com/3gstudent/Office-Persistence)

Detection evasion

* [DoctorLai/VBScript_Obfuscator - The VBScript Obfuscator written in VBScript](https://github.com/DoctorLai/VBScript_Obfuscator)
* [mwrlabs/wePWNise - generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software](https://github.com/mwrlabs/wePWNise)
* [itm4n/VBA-RunPE - A VBA implementation of the RunPE technique or how to bypass application whitelisting](https://github.com/itm4n/VBA-RunPE)
* [nccgroup/demiguise - HTA encryption tool](https://github.com/nccgroup/demiguise)

Macro tools

* [med0x2e/vba2clr - Running .NET from VBA](https://github.com/med0x2e/vba2clr)
* [optiv/Ivy - Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory. Ivy’s loader does this by utilizing programmatical access in the VBA object environment to load, decrypt and execute shellcode](https://github.com/optiv/Ivy)
* [optiv/Dent - A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors](https://github.com/optiv/Dent)
* [gist: Philts/Invoke-ExShellcode.ps1 - Lateral movement and shellcode injection via Excel 4.0 macros - RtlCopyMemory + QueueUserAPC + NtTestAlert方式执行shellcode](https://gist.github.com/Philts/f7c85995c5198e845c70cc51cd4e7e2a)
* [whitel1st/docem - Uility to embed XXE and XSS payloads in docx,odt,pptx,etc (OXML_XEE on steroids)](https://github.com/whitel1st/docem)
* [0xdeadbeefJERKY/Office-DDE-Payloads - Collection of scripts and templates to generate Office documents embedded with the DDE, macro-less command execution techniqu](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)
* [michaelweber/Macrome - Excel Macro Document Reader/Writer for Red Teamers & Analysts](https://github.com/michaelweber/Macrome)
* [Shellntel/luckystrike - A PowerShell based utility for the creation of malicious Office macro documents](https://github.com/Shellntel/luckystrike)
* [cldrn/macphish - Office for Mac Macro Payload Generator](https://github.com/cldrn/macphish)
* [sevagas/macro_pack - a tool used to automatize obfuscation and generation of MS Office documents](https://github.com/sevagas/macro_pack)
* [Mr-Un1k0d3r/MaliciousMacroGenerator - Malicious Macro Generator (支持VM检测)](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)
* [Pepitoh/VBad - VBA Obfuscation Tools combined with an MS office document generator](https://github.com/Pepitoh/VBad)
* [enigma0x3/Generate-Macro - This Powershell script will generate a malicious Microsoft Office document with a specified payload and persistence method](https://github.com/enigma0x3/Generate-Macro)
* [outflanknl/EvilClippy - A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows](https://github.com/outflanknl/EvilClippy)
* [FortyNorthSecurity/EXCELntDonut - Excel 4.0 (XLM) Macro Generator for injecting DLLs and EXEs into memory](https://github.com/FortyNorthSecurity/EXCELntDonut)
* [JanKallman/EPPlus - Create advanced Excel spreadsheets using .NET - 这个工具独立于微软的库，可以避免 PerformanceCache 和 CompressedSourceCode，没有这两个可以免杀](https://github.com/JanKallman/EPPlus)
  * [Evidence of VBA Purging Found in Malicious Documents](https://blog.nviso.eu/2020/02/25/evidence-of-vba-purging-found-in-malicious-documents/)
* [christophetd/spoofing-office-macro - VBA macro spawning a process with a spoofed parent and command line](https://github.com/christophetd/spoofing-office-macro)
* [khr0x40sh/MacroShop - Collection of scripts to aid in delivering payloads via Office Macros](https://github.com/khr0x40sh/MacroShop)
* [1d8/macros - Social Engineering Using "Hidden" Macros In Excel](https://github.com/1d8/macros)
* [FortyNorthSecurity/hot-manchego - Macro-Enabled Excel File Generator (.xlsm) using the EPPlus Library](https://github.com/FortyNorthSecurity/hot-manchego)
* VBA
  * [fireeye/OfficePurge - removes P-code from module streams within Office documents - 有博客说明，删除PerformanceCache后只有CompressedSourceCode字段，导致yara规则无法匹配关键词，从而绕过检测](https://github.com/fireeye/OfficePurge)
  * [MalwareCantFly/Vba2Graph - Generate call graphs from VBA code, for easier analysis of malicious documents](https://github.com/MalwareCantFly/Vba2Graph) 
  * [glinares/VBA-Stendhal - Inject Encrypted Commands Into EMF Shapes for C2 In VBA / Office Malware](https://github.com/glinares/VBA-Stendhal)
  * [mgeeky/RobustPentestMacro - This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques](https://github.com/mgeeky/RobustPentestMacro)
  * [rmdavy/HeapsOfFun - AMSI Bypass Via the Heap](https://github.com/rmdavy/HeapsOfFun)
  * [bonnetn/vba-obfuscator - 2018 School project - PoC of malware code obfuscation in Word macros](https://github.com/bonnetn/vba-obfuscator)
 
Payload analysis

* [bontchev/pcodedmp - A VBA p-code disassembler](https://github.com/bontchev/pcodedmp)
* [decalage2/ViperMonkey - A VBA parser and emulation engine to analyze malicious macros](https://github.com/decalage2/ViperMonkey)
* [tehsyntx/loffice - Lazy Office Analyzer](https://github.com/tehsyntx/loffice)
* [eset/vba-dynamic-hook - VBA Dynamic Hook dynamically analyzes VBA macros inside Office documents by hooking function calls](https://github.com/eset/vba-dynamic-hook)
* [DissectMalware/XLMMacroDeobfuscator - Extract and Deobfuscate XLM macros (a.k.a Excel 4.0 Macros)](https://github.com/DissectMalware/XLMMacroDeobfuscator)
* [decalage2/oletools - python tools to analyze MS OLE2 files](https://github.com/decalage2/oletools)
  * [mraptor](https://github.com/decalage2/oletools/wiki/mraptor)
  * [olevba](https://github.com/decalage2/oletools/wiki/olevba)
  * [decompress_rtf.py - compressed RTF analyzer](https://blog.didierstevens.com/2018/10/22/new-tool-decompress_rtf-py/)
  * [oledump](https://blog.didierstevens.com/programs/oledump-py/)
* [egaus/MaliciousMacroBot - malicious office documents triage tool](https://github.com/egaus/MaliciousMacroBot)
* [edeca/rtfraptor - Extract OLEv1 objects from RTF files by instrumenting Word](https://github.com/edeca/rtfraptor)
* [bsi-group/officefileinfo - a python script to help analyse the newer Microsoft Office file formats](https://github.com/bsi-group/officefileinfo)
* [tylabs/quicksand - QuickSand document and PDF malware analysis tool written in Python](https://github.com/tylabs/quicksand)

Sandbox detection / escape

* [joesecurity/pafishmacro - Pafish Macro is a Macro enabled Office Document to detect malware analysis systems and sandboxes. It uses evasion & detection techniques implemented by malicious documents](https://github.com/joesecurity/pafishmacro)
* [Documents of Doom infecting macOS via office macros - 虽然Mac版本office有沙箱，但只要包含 ~$ 字样都允许写入，所以可以用 ~$com.xpnsec.plist 这样的文件名来绕过限制](https://objectivebythesea.com/v3/talks/OBTS_v3_pWardle.pdf)
* [certego: Advanced VBA macros: bypassing olevba static analyses with 0 hits - 2020.7的，用冷门API和事件绕过检测](https://www.certego.net/en/news/advanced-vba-macros/)
* [gist: X-C3LL/hookdetector.vba - VBA Macro to detect EDR Hooks (It's just a PoC)](https://gist.github.com/X-C3LL/7bb17ecf01f59f50ad52569467af68d6)

Office 365 / O365

* [T0pCyber/hawk - Powershell Based tool for gathering information related to O365 intrusions and potential Breaches - 微软员工出的](https://github.com/T0pCyber/hawk)
* [mrrothe/py365 - A tool for finding risky or suspicious inbox rules](https://github.com/mrrothe/py365)
* [mdsecactivebreach/o365-attack-toolkit - A toolkit to attack Office365](https://github.com/mdsecactivebreach/o365-attack-toolkit)
* [LMGsec/o365creeper - Python script that performs email address validation against Office 365 without submitting login attempts](https://github.com/LMGsec/o365creeper)
* [busterb/msmailprobe - Office 365 and Exchange Enumeration](https://github.com/busterb/msmailprobe)
* [nyxgeek/o365recon - retrieve information via O365 with a valid cred](https://github.com/nyxgeek/o365recon)
* [LMGsec/O365-Lockdown - Secure and log available activities in your Microsoft Office 365 environment](https://github.com/LMGsec/O365-Lockdown)
* [vysec/checkO365 - a tool to check if a target domain is using O365](https://github.com/vysec/checkO365)
* [LMGsec/Magic-Unicorn-Tool - This is the beta release of our Office 365 Activities API report parsing tool](https://github.com/LMGsec/Magic-Unicorn-Tool)
* [grimhacker/office365userenum - Enumerate valid usernames from Office 365 using ActiveSync](https://bitbucket.org/grimhacker/office365userenum/src/master/)

Lync

* [mdsecresearch/LyncSniper - A tool for penetration testing Skype for Business and Lync deployments](https://github.com/mdsecresearch/LyncSniper)
* [nyxgeek/lyncsmash - locate and attack Lync/Skype for Business](https://github.com/nyxgeek/lyncsmash)

Uncategorized

* [r00t-3xp10it/backdoorppt - transform your payload.exe into one fake word doc (.ppt)](https://github.com/r00t-3xp10it/backdoorppt)
* [sensepost/SPartan - Frontpage and Sharepoint fingerprinting and attack tool](https://github.com/sensepost/SPartan)
* [byt3bl33d3r/SprayingToolkit - Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient](https://github.com/byt3bl33d3r/SprayingToolkit)
* [rtfdump](https://blog.didierstevens.com/2017/12/10/update-rtfdump-py-version-0-0-6/)
* [colemination/PowerOutlook - Sample code from Owning MS Outlook with Powershell](https://github.com/colemination/PowerOutlook)
* [nolze/msoffcrypto-tool - A Python tool and library for decrypting MS Office files - Excel 通用默认密码 VelvetSweatshop](https://github.com/nolze/msoffcrypto-tool)
  * 测试样本hash: a42bb4900131144aaee16d1235a22ab6d5af43407a383c3d17568dc7cfe10e64 (CDFV2 Encrypted)

## References

* [MS OFFICE IN WONDERLAND](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf)
* [DerbyCon2018 - The MS Office Magic Show](https://github.com/outflanknl/Presentations/blob/master/DerbyCon_2018_The_MS_Office_Magic_Show.pdf)
* [THC 2017 - VBA Macros Pest Control](https://www.decalage.info/files/THC17_Lagadec_Macro_Pest_Control2.pdf)
* [Evolution of Excel 4.0 Macro Weaponization](https://vblocalhost.com/uploads/VB2020-61.pdf)
  * [Evolution of Excel 4.0 Macro Weaponization - 网页版](https://www.lastline.com/labsblog/evolution-of-excel-4-0-macro-weaponization/)


