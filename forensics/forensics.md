# opensource-forensics-tools

A collection of open source forensics tools

## Collections

3rd-party lists

* [alphaSeclab/awesome-forensics - Awesome Forensics Resources](https://github.com/alphaSeclab/awesome-forensics)
* [FreeBUF: 安全应急响应工具年末大放送（含下载）](http://www.freebuf.com/sectool/87400.html)
* [meirwah/awesome-incident-response - A curated list of tools for incident response](https://github.com/meirwah/awesome-incident-response)
* [Bellingcat's Digital Forensics Tools](https://docs.google.com/document/d/1BfLPJpRtyq4RFtHJoNpvWQjmGnyVkfE2HYoICKOGguA/edit)
* [Eric Zimmerman's tools - .net 4.6 开发的，各种提取特征的工具](https://ericzimmerman.github.io/#!index.md)
  * [EricZimmermanCommandLineToolsCheatSheet-v1.0.pdf - 一些工具的说明](https://digital-forensics.sans.org/media/EricZimmermanCommandLineToolsCheatSheet-v1.0.pdf)

Online services

* [Microsoft Freta - Linux 内存分析工具，能够枚举文件、socket、syscall表是否被JMP跳转、被调试的进程等等，在线服务](https://freta.azurewebsites.net/)

Suite

* [Velocidex/velociraptor - Endpoint visibility and collection tool - 2.1K star](https://github.com/Velocidex/velociraptor)
* [BlackINT3/OpenArk - OpenArk is an open source anti-rookit(ARK) tool for Windows - 3.4K star，有界面](https://github.com/BlackINT3/OpenArk)
* [google/timesketch - Collaborative forensic timeline analysis - 1.9K star](https://github.com/google/timesketch)
  * https://zawadidone.nl/automating-dfir-using-cloud-services/
* [fireeye/rVMI - A New Paradigm For Full System Analysis](https://github.com/fireeye/rVMI)
* [CERTCC/trommel - Sift Through Embedded Device Files to Identify Potential Vulnerable Indicators](https://github.com/CERTCC/trommel)
* [rough007/CDQR - a fast and easy to use forensic artifact parsing tool that works on disk images, mounted drives and extracted artifacts from Windows, Linux and MacOS devices](https://github.com/rough007/CDQR)
* [biggiesmallsAG/nightHawkResponse - Incident Response Forensic Framework](https://github.com/biggiesmallsAG/nightHawkResponse)
* [google/grr - Rapid Response: remote live forensics for incident response](https://github.com/google/grr)
* [davehull/Kansa - A Powershell incident response framework](https://github.com/davehull/Kansa)
* [DFIRKuiper/Kuiper - Digital Investigation Platform - 看说明这个检查点挺全的](https://github.com/DFIRKuiper/Kuiper)
* [vitaly-kamluk/bitscout - Remote forensics meta tool](https://github.com/vitaly-kamluk/bitscout)
* [intezer/linux-explorer - Easy-to-use live forensics toolbox for Linux endpoints](https://github.com/intezer/linux-explorer)

Memory forensics

* [Magnet RAM Capture - Windows GUI程序，输出内容volatity可解析](https://magnetforensics.com/resources/magnet-ram-capture)
* [mlcsec/proctools - Small toolkit for extracting information and dumping sensitive strings from Windows processes](https://github.com/mlcsec/proctools)
* [forrest-orr/moneta - Moneta is a live usermode memory analysis tool for Windows with the capability to detect malware IOCs - 用PSAPI_WORKING_SET_EX_INFORMATION判断页面是否发生过CopyOnWrite，如果发生过说明内存被修改过（比如DLL HOOK）。这个EDR场景可能会误报](https://github.com/forrest-orr/moneta)
* [CodeCracker-Tools/MegaDumper - Dump native and .NET assemblies - 注入到unmanaged程序的情况无法dump](https://github.com/CodeCracker-Tools/MegaDumper)
* [whatsbcn/skpd - Process dump to executable ELF for linux - 2013停更](https://github.com/whatsbcn/skpd)
* [kd8bny/LiMEaide - A python application designed to remotely dump RAM of a Linux client and create a volatility profile for later analysis on your local host](https://github.com/kd8bny/LiMEaide)
* [ProjectRetroScope/RetroScope - Android memory forensics framework](https://github.com/ProjectRetroScope/RetroScope)
* [gleeda/memtriage - Allows you to quickly query a Windows machine for RAM artifacts](https://github.com/gleeda/memtriage)
* [google/rekall - Rekall Memory Forensic Framework](https://github.com/google/rekall)
  * [toolsmith – Hunting In-Memory Adversaries with Rekall and WinPmem](https://holisticinfosec.org/toolsmith/pdf/may2015.pdf)
  * [fireeye/win10_rekall - Rekall with Windows 10 Memory Compression - FireEye 加入了 Win10 内存压缩支持](https://github.com/fireeye/win10_rekall)
* [ufrisk/MemProcFS - The Memory Process File System](https://github.com/ufrisk/MemProcFS)
* [comaeio/LiveCloudKd - Hyper-V Research is trendy now](https://github.com/comaeio/LiveCloudKd)
* [Extracting Activity History from PowerShell Process Dumps - 没给工具，用WinDBG解析powershell内存，提取HistoryInfo](http://www.leeholmes.com/blog/2019/01/04/extracting-activity-history-from-powershell-process-dumps/)
* [marcosd4h/memhunter - Live hunting of code injection techniques](https://github.com/marcosd4h/memhunter)

Registry

* [khyrenz/parseusbs - Parses USB connection artifacts from offline Registry hives](https://github.com/khyrenz/parseusbs)

Filesystem

* [KBNLresearch/isolyzer - Verify size of ISO 9660 image against Volume Descriptor fields](https://github.com/KBNLresearch/isolyzer)
* [mnrkbys/vss_carver - Carves and recreates VSS catalog and store from Windows disk image](https://github.com/mnrkbys/vss_carver)
* [mregmi/ext2read - A Windows Application to read and copy Ext2/Ext3/Ext4 (With LVM) Partitions from Windows](https://github.com/mregmi/ext2read)

Mobile

* [libimobiledevice - A cross-platform protocol library to communicate with iOS devices - 6K star](https://github.com/libimobiledevice/libimobiledevice)
* [mvt-project/mvt - MVT is a forensic tool to look for signs of infection in smartphone devices - Android/IOS都支持，9.3K star](https://github.com/mvt-project/mvt)
  * https://securelist.com/operation-triangulation/109842/
* [RealityNet/android_triage - Bash script to extract data from an Android device](https://github.com/RealityNet/android_triage)
* WhatsApp
  * [andreas-mausch/whatsapp-viewer - Small tool to display chats from the Android msgstore.db database (crypt12)](https://github.com/andreas-mausch/whatsapp-viewer)
  * [B16f00t/whapa - WhatsApp Parser Tool v0.2](https://github.com/B16f00t/whapa)
  * [Extracting WhatsApp messages from an iOS backup](https://yasoob.me/posts/extracting-whatsapp-messages-from-ios-backup/)
  * [mazen160/whatsapp-chat-parser - WhatsApp Chat Parser - py3实现](https://github.com/mazen160/whatsapp-chat-parser)
  * [romanzaikin/BurpExtension-WhatsApp-Decryption-CheckPoint](https://github.com/romanzaikin/BurpExtension-WhatsApp-Decryption-CheckPoint)

Network

* [netresec.com: findject.py - a simple python script that can find injected TCP packets in HTTP sessions, such as the QUANTUMINSERT Man-on-the-Side (MOTS) attacks](https://www.netresec.com/?page=findject)
* [Srinivas11789/PcapXray - A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction](https://github.com/Srinivas11789/PcapXray)
* [odedshimon/BruteShark - a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files)](https://github.com/odedshimon/BruteShark)

Photograph

* [GuidoBartoli/sherloq - An open-source digital image forensic toolset - Photogrammetry, Photographic Comparison, Content Analysis, and Image Authentication - QT写的，有个截图，1.1K star](https://github.com/GuidoBartoli/sherloq)

Uncategorized

* [SpenserCai/GoWxDump - SharpWxDump的Go语言版。微信客户端取证，获取信息(微信号、手机号、昵称)，微信聊天记录分析(Top N聊天的人、统计聊天最频繁的好友排行、关键词列表搜索等)](https://github.com/SpenserCai/GoWxDump)
  * https://github.com/AdminTest0/SharpWxDump
* [Data Security on Mobile Devices: Current State of the Art, Open Problems, and Proposed Solutions](https://securephones.io/main.pdf)
* [jipegit/OSXAuditor - OS X Auditor is a free Mac OS X computer forensics tool](https://github.com/jipegit/OSXAuditor)
* [ForensicArtifacts/artifacts - Digital Forensics Artifact Repository](https://github.com/ForensicArtifacts/artifacts)
* [Netflix-Skunkworks/diffy - Diffy is a triage tool used during cloud-centric security incidents, to help digital forensics and incident response (DFIR) teams quickly identify suspicious hosts on which to focus their response](https://github.com/Netflix-Skunkworks/diffy)
* [mattifestation/TCGLogTools - A set of tools to retrieve and parse TCG measured boot logs](https://github.com/mattifestation/TCGLogTools)
* [RealityNet/hotoloti - documentation, scripts, tools related to Zena Forensics - 2017停更](https://github.com/RealityNet/hotoloti)

## Resources

Uncategorized

* [OSX (Mac) Memory Acquisition and Analysis Using OSXpmem and Volatility](https://ponderthebits.com/2017/02/osx-mac-memory-acquisition-and-analysis-using-osxpmem-and-volatility/)
* [Mobile Incident Response Overview](https://books.nowsecure.com/mobile-incident-response/en/overview/index.html)
* [Cache Me If You Can - by 505Forensics](https://speakerdeck.com/505forensics/cache-me-if-you-can)
* [Advanced smartphone forensics - Apple iCloud: backups, document storage, keychain; BlackBerry 10 backup encryption ](https://www.troopers.de/media/filer_public/48/4e/484ec809-8c6c-413b-a538-abb3e24231fd/troopers14-advanced_smartphone_forensics-vladimir_katalov.pdf)
* [Logs Unite! - Forensic Analysis of Apple Unified Logs - by mac4n6](https://github.com/mac4n6/Presentations/blob/master/Logs%20Unite!%20-%20Forensic%20Analysis%20of%20Apple%20Unified%20Logs/LogsUnite.pdf)
* [DIGITAL FORENSICS – ARTIFACTS OF INTERACTIVE SESSIONS](https://countuponsecurity.com/2017/11/22/digital-forensics-artifacts-of-interactive-sessions/)
* [ANALYSIS OF THE AMCACHE](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf)

Case study

* [volatility-labs.blogspot.com: When Anti-Virus Engines Look Like Kernel Rootkits - 内存SSDT钩子分析案例](https://volatility-labs.blogspot.com/2020/05/when-anti-virus-engines-look-like.html)
* [5h3r10ck/CTF_Writeups/InCTF - dumpfiles 案例](https://github.com/5h3r10ck/CTF_Writeups/tree/master/InCTF)
* [Masking Malicious Memory Artifacts – Part III: Bypassing Defensive Scanners](https://securityboulevard.com/2020/08/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners/)


