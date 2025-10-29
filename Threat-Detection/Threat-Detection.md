3rd-party Lists

* [Threat Matrix for Storage Services](https://microsoft.github.io/Threat-matrix-for-storage-services/)
* [MHaggis/hunt-detect-prevent - Lists of sources and utilities utilized to hunt, detect and prevent evildoers](https://github.com/MHaggis/hunt-detect-prevent)
* [0x4D31/awesome-threat-detection - A curated list of awesome threat detection and hunting resources](https://github.com/0x4D31/awesome-threat-detection)
* [olafhartong/detection-sources - a linkdump with locations to find great new idea's for developing detection content](https://github.com/olafhartong/detection-sources)
* [infosecn1nja/awesome-mitre-attack - Awesome Mitre ATT&CK™ Framework](https://github.com/infosecn1nja/awesome-mitre-attack)
* [threat-hunting/awesome_Threat-Hunting - A curated list of the most important and useful resources about Threat Detection,Hunting and Intelligence](https://github.com/threat-hunting/awesome_Threat-Hunting)

Frameworks

* [palantir/alerting-detection-strategy-framework - A framework for developing alerting and detection strategies for incident response](https://github.com/palantir/alerting-detection-strategy-framework)

Rules

* [infosecB/Rulehound - An index of publicly available and open-source threat detection rulesets.](https://github.com/infosecB/Rulehound)
* [advanced-threat-research/Yara-Rules - Repository of YARA rules made by McAfee ATR Team](https://github.com/advanced-threat-research/Yara-Rules)
* [countercept/doublepulsar-detection-script - A python2 script for sweeping a network to find windows systems compromised with the DOUBLEPULSAR implant](https://github.com/countercept/doublepulsar-detection-script)
* [f-secure: Detecting Exposed Cobalt Strike DNS Redirectors](https://labs.f-secure.com/blog/detecting-exposed-cobalt-strike-dns-redirectors/)

Syntax Parsers

* [kaitai-io/kaitai_struct - Kaitai Struct: declarative language to generate binary data parsers in C++ / C# / Go / Java / JavaScript / Lua / Perl / PHP / Python / Ruby](https://github.com/kaitai-io/kaitai_struct)

Online Scanners

* APK
  * [Koodous](https://koodous.com/)
* Office
  * [Office document malware analysis](https://quicksand.io/)

URL Security

* https://urlscan.io/
* [afilipovich/gglsbl - Python client library for Google Safe Browsing API](https://github.com/afilipovich/gglsbl)

Windows

* [hasherezade/pe-sieve - Scans a given process, searching for the modules containing in-memory code modifications. When found, it dumps the modified PE - 能够发现并dump内存hook、shellcode、sleep beacon，效果还可以](https://github.com/hasherezade/pe-sieve)
* [waldo-irc/MalMemDetect - Detect strange memory regions and DLLs - hook sleep、VirtualAlloc等函数，检查调用来源是否为DLL模块](https://github.com/waldo-irc/MalMemDetect)
* [huoji120/DuckMemoryScan - 遍历线程，搜索MZ字样 - 大把大把的误报，而且太容易绕过，仅作为参考](https://github.com/huoji120/DuckMemoryScan)
* [DamonMohammadbagher/Meterpreter_Payload_Detection - Meterpreter_Payload_Detection.exe tool for detecting Meterpreter in memory like IPS-IDS and Forensics tool - ETW监控线程创建，然后内存特征码搜索](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)
* [countercept/ppid-spoofing - Scripts for performing and detecting parent PID spoofing - 基于ETW的，不确定是否会有误报](https://github.com/countercept/ppid-spoofing)
* [hzqst/Syscall-Monitor - a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+](https://github.com/hzqst/Syscall-Monitor)
* [D4stiny/PeaceMaker - a Windows kernel-based application that detects advanced techniques used by malware - 主要是进程相关，比如设置父进程、线程注入等等，应该误报比较多](https://github.com/D4stiny/PeaceMaker)
* [google/ukip - USB Keystroke Injection Protection](https://github.com/google/ukip)
* [matt2005/InjectionHunter - 貌似是检测 powershell 注入的](https://github.com/matt2005/InjectionHunter)
* Spoofing detection
  * [joda32/got-responded - A simple tool to detect NBT-NS and LLMNR spoofing (and messing with them a bit)](https://github.com/joda32/got-responded)

Linux Auditd
 
* [linux-audit/audit-userspace/rules - auditd 一些规则，稍微有点用](https://github.com/linux-audit/audit-userspace/tree/master/rules)
* [Neo23x0/auditd - Best Practice Auditd Configuration - 过滤规则很有价值](https://github.com/Neo23x0/auditd)
* [bfuzzy/auditd-attack - A Linux Auditd rule set mapped to MITRE's Attack Framework](https://github.com/bfuzzy/auditd-attack)
* [threathunters-io/laurel - Transform Linux Audit logs for SIEM usage](https://github.com/threathunters-io/laurel/)

Mac

* [objective-see/ReiKey - Malware and other applications may install persistent keyboard "event taps" to intercept your keystrokes. ReiKey can scan, detect, and monitor for such taps!](https://github.com/objective-see/ReiKey)
* [SuprHackerSteve/Crescendo - a swift based, real time event viewer for macOS. It utilizes Apple's Endpoint Security Framework - 2020停更，基于Endpoint Security Framework开发的](https://github.com/SuprHackerSteve/Crescendo)
* [theevilbit/Shield - An app to protect against process injection on macOS](https://github.com/theevilbit/Shield)

Detect Obfuscation

* [We5ter/Flerken - Open-Source Obfuscated Command Detection Tool](https://github.com/We5ter/Flerken)

Log Collecting

* [palantir/windows-event-forwarding - A repository for using windows event forwarding for incident detection and response](https://github.com/palantir/windows-event-forwarding)
* [Windows Event Forwarding for Network Defense](https://medium.com/@palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
* [iadgov/Event-Forwarding-Guidance - Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding. iadgov](https://github.com/iadgov/Event-Forwarding-Guidance)

Log Analysis

* [WINDOWS REGISTRY AUDITING CHEAT SHEET - Win 7/Win 2008 or later](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows)
* [WINDOWS ATT&CK LOGGING CHEAT SHEET - Win 7 - Win 2012 - ATT&CK模型，以及对应的日志编号，很有用](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5b8f091c0ebbe8644d3a886c/1536100639356/Windows+ATT&CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf)
* [WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf)
* [Public_Windows Event Log Zero 2 Hero Slides - 常见恶意行为日志说明，搜索语句以及识别方法](https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit#slide=id.g21acf94f3f_2_27)
* [kitabisa/teler - Real-time HTTP Intrusion Detection - 规则说是首次联网下载](https://github.com/kitabisa/teler)
  * [kitabisa/teler-resources - teler Resource Collections](https://github.com/kitabisa/teler-resources)

Network

* [codeexpress/respounder - detects presence of responder in the network](https://github.com/codeexpress/respounder)
* [europa502/shARP - An anti-ARP-spoofing application software that use active and passive scanning methods to detect and remove any ARP-spoofer from the network](https://github.com/europa502/shARP)

Monitoring

* [realparisi/WMI_Monitor - Log newly created WMI consumers and processes](https://github.com/realparisi/WMI_Monitor)
* [luctalpe/WMIMon - Tool to monitor WMI activity on Windows](https://github.com/luctalpe/WMIMon)
* [9b/chirp - Interface to manage and centralize Google Alert information](https://github.com/9b/chirp)
* [elastic/beats - Beats - Lightweight shippers for Elasticsearch & Logstash](https://github.com/elastic/beats)
* [dgunter/evtxtoelk - A lightweight tool to load Windows Event Log evtx files into Elasticsearch](https://github.com/dgunter/evtxtoelk)
* [outflanknl/RedELK - tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations](https://github.com/outflanknl/RedELK)
* Github
  * [FeeiCN/GSIL - GitHub Sensitive Information Leakage（GitHub敏感信息泄露监控）](https://github.com/FeeiCN/GSIL)
  * [MiSecurity/x-patrol - github泄露扫描系统](https://github.com/MiSecurity/x-patrol)
  * [neal1991/gshark - Scan for sensitive information in Github easily and effectively](https://github.com/neal1991/gshark)
  * [0xbug/Hawkeye - GitHub 泄露监控系统 - 有界面，star 很多](https://github.com/0xbug/Hawkeye)
* Zabbix plugin
  * [vulnersCom/zabbix-threat-control - Zabbix vulnerability assessment plugin](https://github.com/vulnersCom/zabbix-threat-control)
* ElasticSearch addons
  * [NVISO-BE/ee-outliers - Open-source framework to detect outliers in Elasticsearch events](https://github.com/NVISO-BE/ee-outliers)

Signature

* [fireeye/red_team_tool_countermeasures](https://github.com/fireeye/red_team_tool_countermeasures)
* [mattifestation/file-getpefeature-ps1 - Retrieves key features from PE files that can be used to build detections](https://gist.github.com/mattifestation/3dc9ece6ee04be62ec8df16bf1047436#file-getpefeature-ps1)
* [avast/yari - YARI is an interactive debugger for YARA Language](https://github.com/avast/yari)
* [CERT-Polska/mquery - YARA malware query accelerator (web frontend)](https://github.com/CERT-Polska/mquery)
* [botherder/kraken - Cross-platform Yara scanner written in Go](https://github.com/botherder/kraken)
* [Neo23x0/yarGen - a generator for YARA rules](https://github.com/Neo23x0/yarGen)
* [InQuest/yara-rules - A collection of YARA rules we wish to share with the world](https://github.com/InQuest/yara-rules)
* [Neo23x0/panopticon - A YARA Rule Performance Measurement Tool](https://github.com/Neo23x0/panopticon)
* [Yara-Rules/rules - Repository of yara rules](https://github.com/Yara-Rules/rules)

Security intelligence / feeds

* [NVD Data Feeds - Dependency Check在用这个](https://nvd.nist.gov/vuln/data-feeds)
* [TheHive-Project/Hippocampe - Threat Feed Aggregation, Made Easy](https://github.com/TheHive-Project/Hippocampe)
* [MISP - Open Source Threat Intelligence Platform (formely known as Malware Information Sharing Platform) - 3.6K star](https://github.com/MISP/MISP)

Uncategorized

* [rabobank-cdc/DeTTECT - Detect Tactics, Techniques & Combat Threats](https://github.com/rabobank-cdc/DeTTECT)
* [christophetd/hunting-mindmaps - Mindmaps for threat hunting - WIP](https://github.com/christophetd/hunting-mindmaps)
* [microsoft/msticpy - Microsoft Threat Intelligence Security Tools](https://github.com/microsoft/msticpy)
* [target/strelka - a real-time file scanning system used for threat hunting, threat detection, and incident response](https://github.com/target/strelka)
* [phishai/phish-protect - Chrome extension to alert and possibly block IDN/Unicode websites and zero-day phishing websites using AI and Computer Vision](https://github.com/phishai/phish-protect)
* [Cyb3rWard0g/HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
   * [toolsmith #131 - The HELK vs APTSimulator - Part 1](https://holisticinfosec.blogspot.com.au/2018/02/toolsmith-131-helk-vs-aptsimulator-part.html)
* [endgameinc/ClrGuard - a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes - AppInit注入DLL，然后检测CLR加载事件](https://github.com/endgameinc/ClrGuard)

Resources

* [Sensitive Command Token - So much offense in my defense - 用IFEO实现whoami执行监控，然后通过powershell上报到canaryoken系统，实现简陋的EDR](https://blog.thinkst.com/2022/09/sensitive-command-token-so-much-offense.html)
* [workshop: RESOLVN/RTHVM - The Resolvn Threat Hunting Virtual Machine (RTHVM) is a training resource used during a 2019 Packet Hacking Village workshop titled Intel-driven Hunts for Nation-state Activity Using Elastic SIEM - 介绍了多个日志查询案例，比如存活较短的计划任务](https://github.com/RESOLVN/RTHVM)
* [blackhat eu-17: Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
* [defcon25: MS Just Gave the Blue Team Tactical Nukes (And How Red Teams Need To Adapt)](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Chris-Thompson-MS-Just-Gave-The-Blue-Teams-Tactical-Nukes-UPDATED.pdf)
* [PART 1: How I Met Your Beacon – Overview - 这个有个x33fcon的pdf](https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/)
* Just-Hack-For-Fun 说是应急响应手册，实际更像是实验环境的学习手册(全是Ubuntu)。并非操作框架，内容比较水，适合刚入门的安全工程师查看
  * https://github.com/Just-Hack-For-Fun/Windows-INCIDENT-RESPONSE-COOKBOOK
  * https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK
* [Tales of a Threat Hunter 2 - Following the trace of WMI Backdoors & other nastiness](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [awslabs/aws-security-automation - Collection of scripts and resources for DevSecOps and Automated Incident Response Security](https://github.com/awslabs/aws-security-automation)
* [mitre/attack-navigator - Web app that provides basic navigation and annotation of ATT&CK matrices](https://github.com/mitre/attack-navigator)
* [Disrupting the Empire: Identifying PowerShell Empire Command and Control Activity](https://www.sans.org/reading-room/whitepapers/incident/disrupting-empire-identifying-powershell-empire-command-control-activity-38315)
* [speakerdeck: Hunting for Privilege Escalation in Windows Environment - 使用sysmon+ELK检测各种提权](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
* [AWS Security Incident Response](https://d1.awsstatic.com/whitepapers/aws_security_incident_response.pdf)
* [speakerdeck: Hunting for Privilege Escalation in Windows Environment - 根据日志分析提权，没有实际的大规模应用例子，只是留个记录](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
* [OWASP - Automated Threat Handbook - Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications)
