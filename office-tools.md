# opensource-office-tools

A collection of office tools

## Macro tools

Macro tools

* [0xdeadbeefJERKY/Office-DDE-Payloads - Collection of scripts and templates to generate Office documents embedded with the DDE, macro-less command execution techniqu](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)
* [michaelweber/Macrome - Excel Macro Document Reader/Writer for Red Teamers & Analysts](https://github.com/michaelweber/Macrome)
* [Shellntel/luckystrike - A PowerShell based utility for the creation of malicious Office macro documents](https://github.com/Shellntel/luckystrike)
* [cldrn/macphish - Office for Mac Macro Payload Generator](https://github.com/cldrn/macphish)
* [sevagas/macro_pack - a tool used to automatize obfuscation and generation of MS Office documents](https://github.com/sevagas/macro_pack)
* [Mr-Un1k0d3r/MaliciousMacroGenerator - Malicious Macro Generator (支持VM检测)](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)
* [Pepitoh/VBad - VBA Obfuscation Tools combined with an MS office document generator](https://github.com/Pepitoh/VBad)
* [enigma0x3/Generate-Macro - This Powershell script will generate a malicious Microsoft Office document with a specified payload and persistence method](https://github.com/enigma0x3/Generate-Macro)
* [mwrlabs/wePWNise - WePWNise generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software](https://github.com/mwrlabs/wePWNise)
* [outflanknl/EvilClippy - A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows](https://github.com/outflanknl/EvilClippy)
* [FortyNorthSecurity/EXCELntDonut - Excel 4.0 (XLM) Macro Generator for injecting DLLs and EXEs into memory](https://github.com/FortyNorthSecurity/EXCELntDonut)
* [JanKallman/EPPlus - Create advanced Excel spreadsheets using .NET - 这个工具独立于微软的库，可以避免 PerformanceCache 和 CompressedSourceCode，没有这两个可以免杀](https://github.com/JanKallman/EPPlus)
  * [Evidence of VBA Purging Found in Malicious Documents](https://blog.nviso.eu/2020/02/25/evidence-of-vba-purging-found-in-malicious-documents/)
* [decalage2/oletools - python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging](https://github.com/decalage2/oletools)
* [christophetd/spoofing-office-macro - VBA macro spawning a process with a spoofed parent and command line](https://github.com/christophetd/spoofing-office-macro)
* [khr0x40sh/MacroShop - Collection of scripts to aid in delivering payloads via Office Macros](https://github.com/khr0x40sh/MacroShop)
* [1d8/macros - Social Engineering Using "Hidden" Macros In Excel](https://github.com/1d8/macros)
* VBA
  * [MalwareCantFly/Vba2Graph - Generate call graphs from VBA code, for easier analysis of malicious documents](https://github.com/MalwareCantFly/Vba2Graph) 
  * [glinares/VBA-Stendhal - Inject Encrypted Commands Into EMF Shapes for C2 In VBA / Office Malware](https://github.com/glinares/VBA-Stendhal)
 
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
* [tylabs/quicksand_lite - Command line tool for scanning streams within office documents plus xor db attack](https://github.com/tylabs/quicksand_lite)

Sandbox detection / escape

* [joesecurity/pafishmacro - Pafish Macro is a Macro enabled Office Document to detect malware analysis systems and sandboxes. It uses evasion & detection techniques implemented by malicious documents](https://github.com/joesecurity/pafishmacro)
* [Documents of Doom infecting macOS via office macros - 虽然Mac版本office有沙箱，但只要包含 ~$ 字样都允许写入，所以可以用 ~$com.xpnsec.plist 这样的文件名来绕过限制](https://objectivebythesea.com/v3/talks/OBTS_v3_pWardle.pdf)
* [certego: Advanced VBA macros: bypassing olevba static analyses with 0 hits - 2020.7的，用冷门API和事件绕过检测](https://www.certego.net/en/news/advanced-vba-macros/)

Password recovery

* [stackoverflow: Is there a way to crack the password on an Excel VBA Project - Excel 2007-2016 VBA 密码不是真的保护，只是一个标志位](https://stackoverflow.com/questions/1026483/is-there-a-way-to-crack-the-password-on-an-excel-vba-project)

Office 365 / O365

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
* [christophetd/spoofing-office-macro - PoC of a VBA macro spawning a process with a spoofed parent and command line](https://github.com/christophetd/spoofing-office-macro)

## References

* [MS OFFICE IN WONDERLAND](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf)
* [DerbyCon2018 - The MS Office Magic Show](https://github.com/outflanknl/Presentations/blob/master/DerbyCon_2018_The_MS_Office_Magic_Show.pdf)
* [THC 2017 - VBA Macros Pest Control](https://www.decalage.info/files/THC17_Lagadec_Macro_Pest_Control2.pdf)

