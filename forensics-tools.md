# opensource-forensics-tools

A collection of open source forensics tools

## Collections

3rd-party lists

* [FreeBUF: 安全应急响应工具年末大放送（含下载）](http://www.freebuf.com/sectool/87400.html)
* [meirwah/awesome-incident-response - A curated list of tools for incident response](https://github.com/meirwah/awesome-incident-response)
* [Bellingcat's Digital Forensics Tools](https://docs.google.com/document/d/1BfLPJpRtyq4RFtHJoNpvWQjmGnyVkfE2HYoICKOGguA/edit)
* [Eric Zimmerman's tools - .net 4.6 开发的，各种提取特征的工具](https://ericzimmerman.github.io/#!index.md)
  * [EricZimmermanCommandLineToolsCheatSheet-v1.0.pdf - 一些工具的说明](https://digital-forensics.sans.org/media/EricZimmermanCommandLineToolsCheatSheet-v1.0.pdf)

Suite

* [fireeye/rVMI - A New Paradigm For Full System Analysis](https://github.com/fireeye/rVMI)
* [CERTCC/trommel - Sift Through Embedded Device Files to Identify Potential Vulnerable Indicators](https://github.com/CERTCC/trommel)
* [rough007/CDQR - a fast and easy to use forensic artifact parsing tool that works on disk images, mounted drives and extracted artifacts from Windows, Linux and MacOS devices](https://github.com/rough007/CDQR)
* [biggiesmallsAG/nightHawkResponse - Incident Response Forensic Framework](https://github.com/biggiesmallsAG/nightHawkResponse)
* [google/grr -Rapid Response: remote live forensics for incident response](https://github.com/google/grr)
* [davehull/Kansa - A Powershell incident response framework](https://github.com/davehull/Kansa)
* [DFIRKuiper/Kuiper - Digital Investigation Platform - 看说明这个检查点挺全的](https://github.com/DFIRKuiper/Kuiper)

Packet injection

* [netresec.com: findject.py - a simple python script that can find injected TCP packets in HTTP sessions, such as the QUANTUMINSERT Man-on-the-Side (MOTS) attacks](https://www.netresec.com/?page=findject)

Memory forensics

* [gleeda/memtriage - Allows you to quickly query a Windows machine for RAM artifacts](https://github.com/gleeda/memtriage)
* [sevagas/swap_digger - a tool used to automate Linux swap analysis during post-exploitation or forensics](https://github.com/sevagas/swap_digger)
* [google/rekall - Rekall Memory Forensic Framework](https://github.com/google/rekall)
  * [toolsmith – Hunting In-Memory Adversaries with Rekall and WinPmem](https://holisticinfosec.org/toolsmith/pdf/may2015.pdf)
  * [fireeye/win10_rekall - Rekall with Windows 10 Memory Compression - FireEye 加入了 Win10 内存压缩支持](https://github.com/fireeye/win10_rekall)
* [volatilityfoundation/volatility - An advanced memory forensics framework](https://github.com/volatilityfoundation/volatility)
  * [fireeye/win10_volatility - Volatility Framework with Windows 10 Memory Compression - FireEye 加入了 Win10 内存压缩支持](https://github.com/fireeye/win10_volatility)
  * [JPCERTCC/MalConfScan - Volatility plugin for extracts configuration data of known malware](https://github.com/JPCERTCC/MalConfScan)
  * [fireeye/win10_auto - currently consists of the FLARE team's Volatility & Rekall plugins designed to support the extraction of compressed pages located in the RAM-backed virtual store](https://github.com/fireeye/win10_auto)
* [ufrisk/MemProcFS - The Memory Process File System](https://github.com/ufrisk/MemProcFS)
* [comaeio/LiveCloudKd - Hyper-V Research is trendy now](https://github.com/comaeio/LiveCloudKd)
* [Extracting Activity History from PowerShell Process Dumps - 没给工具，用WinDBG解析powershell内存，提取HistoryInfo](http://www.leeholmes.com/blog/2019/01/04/extracting-activity-history-from-powershell-process-dumps/)
* [rek7/mXtract - An opensource linux based tool that analyzes and dumps memory](https://github.com/rek7/mXtract)
* [0x7ff/maphys - Accessing physical memory on iOS](https://github.com/0x7ff/maphys)

Windows

* [mohuihui/antispy - 一款完全免费，并且功能强大的手工杀毒辅助工具。她可以枚举系统中隐藏至深的进程、文件、网络连接、内核对象等，并且也可以检测用户态、内核态各种钩子](https://github.com/mohuihui/antispy)
* [abelcheung/rifiuti2 - Windows Recycle Bin analyser - 分析INFO2格式文件的，应该可以替代以前的 del2info 脚本了](https://github.com/abelcheung/rifiuti2)
* [yampelo/beagle - an incident response and digital forensics tool which transforms security logs and data into graphs - 带界面，看着很有用](https://github.com/yampelo/beagle)
* [comaeio/Hibr2Bin - Comae Hibernation File Decompressor](https://github.com/comaeio/Hibr2Bin)
* [ANSSI-FR/bits_parser - Extract BITS jobs from QMGR queue and store them as CSV records](https://github.com/ANSSI-FR/bits_parser)
* [williballenthin/python-evtx - Pure Python parser for recent Windows Event Log files (.evtx)](https://github.com/williballenthin/python-evtx/blob/master/scripts/evtx_dump.py)
* [orlikoski/CyLR - Live Response Collection tool by Alan Orlikoski and Jason Yegge](https://github.com/orlikoski/CyLR)
* [fox-it/danderspritz-evtx - Parse evtx files and detect use of the DanderSpritz eventlogedit module](https://github.com/fox-it/danderspritz-evtx)
* [PowerShellMafia/CimSweep - a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows](https://github.com/PowerShellMafia/CimSweep)
* [mgreen27/Powershell-IR - Invoke-LiveResponse](https://github.com/mgreen27/Powershell-IR)
* [sysinsider/usbtracker - Quick & dirty coded incident response and forensics python script to track USB devices events and artifacts in a Windows OS (Vista and later)](https://github.com/sysinsider/usbtracker)
* [gfoss/PSRecon - gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team](https://github.com/gfoss/PSRecon)
* [B2dfir/wlrip - WaitList.dat Parser](https://github.com/B2dfir/wlrip)
* [mgreen27/Invoke-BitsParser - parse various Windows Background Intelligent Transfer Service (BITS) artefacts](https://github.com/mgreen27/Invoke-BitsParser)
* [williballenthin/process-forest - Reconstruct process trees from event logs](https://github.com/williballenthin/process-forest)
* [Viralmaniar/Remote-Desktop-Caching- - recover old RDP (mstsc) session information in the form of broken PNG files](https://github.com/Viralmaniar/Remote-Desktop-Caching-)
* [ArsenalRecon/Arsenal-Image-Mounter - mounts the contents of disk images as complete disks in Microsoft Windows](https://github.com/ArsenalRecon/Arsenal-Image-Mounter)
* [tokesr/usb_investigator - designed to be able to gather USB-related artifacts from Windows machines. Also script is designed to correlate these informations. So far this is only a collector for Windows evtx-based information](https://github.com/tokesr/usb_investigator)
* SRUM
  * [tvfischer/ps-srum-hunting - PowerShell Script to facilitate the processing of SRUM data for on-the-fly forensics and if needed threat hunting](https://github.com/tvfischer/ps-srum-hunting)
  * [MarkBaggett/srum-dump - A forensics tool to convert the data in the Windows srum (System Resource Usage Monitor) database to an xlsx spreadsheet](https://github.com/MarkBaggett/srum-dump)

Mac

* [n0fate/chainbreaker - Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
* [mdegrazia/OSX-QuickLook-Parser - Parse the Mac Quickook index.sqlite database](https://github.com/mdegrazia/OSX-QuickLook-Parser)
* [gist: dumpNotificationDB.py](https://gist.github.com/CaledoniaProject/e7176eb644e5e78610d9f43cacaeb84b)
* [mac4n6/macMRU-Parser - parse the Most Recently Used (MRU) plist files on macOS into a more human friendly format](https://github.com/mac4n6/macMRU-Parser)
* [dlcowen/FSEventsParser - Parser for OSX/iOS FSEvents Logs](https://github.com/dlcowen/FSEventsParser)
* [ydkhatri/mac_apt - macOS Artifact Parsing Tool](https://github.com/ydkhatri/mac_apt)
* [Yelp/osxcollector - A forensic evidence collection & analysis toolkit for OS X](https://github.com/Yelp/osxcollector)
* [pstirparo/mac4n6 - Collection of forensics artifacs location for Mac OS X and iOS](https://github.com/pstirparo/mac4n6)
* [CrowdStrike/automactc - AutoMacTC: Automated Mac Forensic Triage Collector](https://github.com/CrowdStrike/automactc)

Linux

* [sevagas/swap_digger - a tool used to automate Linux swap analysis during post-exploitation or forensics](https://github.com/sevagas/swap_digger)
* [JPT - A quick & dirty GPT Partition Editor](http://newandroidbook.com/tools/jpt.html)
* [lukdog/backtolife - Memory forensic tool for process resurrection starting from a memory dump](https://github.com/lukdog/backtolife)
* [eurecom-s3/linux_screenshot_xwindows - Volatility plugin to extract X screenshots from a memory dump](https://github.com/eurecom-s3/linux_screenshot_xwindows)
* [korczis/foremost - Foremost is a console program to recover files based on their headers, footers, and internal data structures - 支持从PCAP里提取文件](https://github.com/korczis/foremost)
* [NateBrune/fmem - Linux Kernel Module designed to help analyze volatile memory in the linux kernel](https://github.com/NateBrune/fmem)
* [snovvcrash/usbrip - Simple command line forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux](https://github.com/snovvcrash/usbrip)

Browser

* [Busindre/dumpzilla - Extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers](https://github.com/Busindre/dumpzilla)
* [obsidianforensics/hindsight - Internet history forensics for Google Chrome/Chromium](https://github.com/obsidianforensics/hindsight)

Disk tools

* [KBNLresearch/isolyzer - Verify size of ISO 9660 image against Volume Descriptor fields](https://github.com/KBNLresearch/isolyzer)
* [ntfsfix - Rescuing a broken NTFS filesystem](https://marcan.st/2015/10/rescuing-a-broken-ntfs-filesystem/)

Mobile

* [andreas-mausch/whatsapp-viewer - Small tool to display chats from the Android msgstore.db database (crypt12)](https://github.com/andreas-mausch/whatsapp-viewer)
* [B16f00t/whapa - WhatsApp Parser Tool v0.2](https://github.com/B16f00t/whapa)
* [silentsignal/burp-cfurl-cache - iOS CFURL Cache inspector for Burp Suite](https://github.com/silentsignal/burp-cfurl-cache)

Network

* [Srinivas11789/PcapXray - A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction](https://github.com/Srinivas11789/PcapXray)

Uncategorized

* [Netflix-Skunkworks/diffy - Diffy is a triage tool used during cloud-centric security incidents, to help digital forensics and incident response (DFIR) teams quickly identify suspicious hosts on which to focus their response](https://github.com/Netflix-Skunkworks/diffy)

## Resources

Uncategorized

* [OSX (Mac) Memory Acquisition and Analysis Using OSXpmem and Volatility](https://ponderthebits.com/2017/02/osx-mac-memory-acquisition-and-analysis-using-osxpmem-and-volatility/)
* [Mobile Incident Response Overview](https://books.nowsecure.com/mobile-incident-response/en/overview/index.html)
* [Cache Me If You Can - by 505Forensics](https://speakerdeck.com/505forensics/cache-me-if-you-can)
* [Advanced smartphone forensics - Apple iCloud: backups, document storage, keychain; BlackBerry 10 backup encryption ](https://www.troopers.de/media/filer_public/48/4e/484ec809-8c6c-413b-a538-abb3e24231fd/troopers14-advanced_smartphone_forensics-vladimir_katalov.pdf)
* [Logs Unite! - Forensic Analysis of Apple Unified Logs - by mac4n6](https://github.com/mac4n6/Presentations/blob/master/Logs%20Unite!%20-%20Forensic%20Analysis%20of%20Apple%20Unified%20Logs/LogsUnite.pdf)
* [DIGITAL FORENSICS – ARTIFACTS OF INTERACTIVE SESSIONS](https://countuponsecurity.com/2017/11/22/digital-forensics-artifacts-of-interactive-sessions/)
* [ANALYSIS OF THE AMCACHE](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf)

Windows Guides

* [sbousseaden/Slides/Windows DFIR Events.pdf - 各种 eventlog 事件样例，非常靠谱](https://github.com/sbousseaden/Slides/blob/master/Windows%20DFIR%20Events.pdf)

MacOS Artifacts

* [iOS Forensics Artifacts v0.1](https://docs.google.com/spreadsheets/d/1z-44BUA2AVf8uqnoiDDSi7UxbyWy8KJqK4uaYq_0YYg/edit)
* [Mac OS X Forensics Artifacts](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW_GNGpX8/edit#gid=3)

Volatility

* [Blackhat Asia 2017 - What Malware Authors Don't Want You To Know： Evasive Hollow Process Injection](https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection.pdf)







