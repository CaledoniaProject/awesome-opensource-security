# Windows forensics

ARK

* [AxtMueller/Windows-Kernel-Explorer - A free but powerful Windows kernel research tool](https://github.com/AxtMueller/Windows-Kernel-Explorer)
* [mohuihui/antispy - 一款完全免费，并且功能强大的手工杀毒辅助工具。她可以枚举系统中隐藏至深的进程、文件、网络连接、内核对象等，并且也可以检测用户态、内核态各种钩子](https://github.com/mohuihui/antispy)

Active Directory

* [ANSSI-FR/ADTimeline - Timeline of Active Directory changes with replication metadata](https://github.com/ANSSI-FR/ADTimeline)

Live

* [mgreen27/Powershell-IR - Invoke-LiveResponse](https://github.com/mgreen27/Powershell-IR)
* [orlikoski/CyLR - Live Response Collection tool by Alan Orlikoski and Jason Yegge](https://github.com/orlikoski/CyLR)

Artifact parser - Uncategorized

* [abelcheung/rifiuti2 - Windows Recycle Bin analyser - 分析INFO2格式文件的，应该可以替代以前的 del2info 脚本了](https://github.com/abelcheung/rifiuti2)
* [comaeio/Hibr2Bin - Comae Hibernation File Decompressor](https://github.com/comaeio/Hibr2Bin)
* [ANSSI-FR/bits_parser - Extract BITS jobs from QMGR queue and store them as CSV records](https://github.com/ANSSI-FR/bits_parser)
* [gfoss/PSRecon - gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team](https://github.com/gfoss/PSRecon)
* [B2dfir/wlrip - WaitList.dat Parser](https://github.com/B2dfir/wlrip)
* [mgreen27/Invoke-BitsParser - parse various Windows Background Intelligent Transfer Service (BITS) artefacts](https://github.com/mgreen27/Invoke-BitsParser)
* [Viralmaniar/Remote-Desktop-Caching- - recover old RDP (mstsc) session information in the form of broken PNG files](https://github.com/Viralmaniar/Remote-Desktop-Caching-)
* [ArsenalRecon/Arsenal-Image-Mounter - mounts the contents of disk images as complete disks in Microsoft Windows](https://github.com/ArsenalRecon/Arsenal-Image-Mounter)
* [yampelo/beagle - an incident response and digital forensics tool which transforms security logs and data into graphs - 带界面，看着很有用](https://github.com/yampelo/beagle)
* [sysinsider/usbtracker - Quick & dirty coded incident response and forensics python script to track USB devices events and artifacts in a Windows OS (Vista and later)](https://github.com/sysinsider/usbtracker)
* [mandiant/ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

Artifact parser - EventLog

* [williballenthin/python-evtx - Pure Python parser for recent Windows Event Log files (.evtx)](https://github.com/williballenthin/python-evtx/blob/master/scripts/evtx_dump.py)
* [fox-it/danderspritz-evtx - Parse evtx files and detect use of the DanderSpritz eventlogedit module](https://github.com/fox-it/danderspritz-evtx)
* [williballenthin/process-forest - Reconstruct process trees from event logs](https://github.com/williballenthin/process-forest)
* [0xrawsec/gene - Signature Engine for Windows Event Logs](https://github.com/0xrawsec/gene)

Artifact parser - SRUM

* [tvfischer/ps-srum-hunting - PowerShell Script to facilitate the processing of SRUM data for on-the-fly forensics and if needed threat hunting](https://github.com/tvfischer/ps-srum-hunting)
* [MarkBaggett/srum-dump - A forensics tool to convert the data in the Windows srum (System Resource Usage Monitor) database to an xlsx spreadsheet](https://github.com/MarkBaggett/srum-dump)

USB

* [tokesr/usb_investigator - designed to be able to gather USB-related artifacts from Windows machines. Also script is designed to correlate these informations. So far this is only a collector for Windows evtx-based information](https://github.com/tokesr/usb_investigator)
* [sysinsider/usbtracker - Quick & dirty coded incident response and forensics python script to track USB devices events and artifacts in a Windows OS (Vista and later)](https://github.com/sysinsider/usbtracker)

NTFS

* [jschicht/ExtractUsnJrnl - Tool to extract the $UsnJrnl from an NTFS volume](https://github.com/jschicht/ExtractUsnJrnl)
* [PoorBillionaire/USN-Journal-Parser - Python script to parse the NTFS USN Change Journal - 得先用上面的工具提取 journal，这个脚本不支持直接读取 journal](https://github.com/PoorBillionaire/USN-Journal-Parser)
* [ntfsfix - Rescuing a broken NTFS filesystem](https://marcan.st/2015/10/rescuing-a-broken-ntfs-filesystem/)

WMI

* [PowerShellMafia/CimSweep - a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows](https://github.com/PowerShellMafia/CimSweep)
* [defcon23: WhyMI so Sexy? WMI Attacks, Real-Time Defense, and Advanced Forensic Analysis - WMI也可以配置ACL；可以用WMI实时监控注册表写入](https://repo.zenk-security.com/Forensic/DEFCON-23-WMI-Attacks-Defense-Forensics.pdf)

## Resources

* [sbousseaden/Slides/Windows DFIR Events.pdf - 各种 eventlog 事件样例，非常靠谱](https://github.com/sbousseaden/Slides/blob/master/Windows%20DFIR%20Events.pdf)
* [Digital Forensics and Incident Response - 内容挺全的](https://www.jaiminton.com/cheatsheet/DFIR/)
* [Exploring the Windows Activity Timeline, Part 2: Synching Across Devices - 用处不大](https://www.blackbagtech.com/blog/exploring-the-windows-activity-timeline-part-2-synching-across-devices/)



