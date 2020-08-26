# opensource-threat-detection

A collection of open source threat detection tools

## Collections

3rd-party lists

* [MHaggis/hunt-detect-prevent - Lists of sources and utilities utilized to hunt, detect and prevent evildoers](https://github.com/MHaggis/hunt-detect-prevent)
* [0x4D31/awesome-threat-detection - A curated list of awesome threat detection and hunting resources](https://github.com/0x4D31/awesome-threat-detection)
* [olafhartong/detection-sources - a linkdump with locations to find great new idea's for developing detection content](https://github.com/olafhartong/detection-sources)
* [infosecn1nja/awesome-mitre-attack - Awesome Mitre ATT&CK™ Framework](https://github.com/infosecn1nja/awesome-mitre-attack)
* [threat-hunting/awesome_Threat-Hunting - A curated list of the most important and useful resources about Threat Detection,Hunting and Intelligence](https://github.com/threat-hunting/awesome_Threat-Hunting)

Rules

* [advanced-threat-research/Yara-Rules - Repository of YARA rules made by McAfee ATR Team](https://github.com/advanced-threat-research/Yara-Rules)
* [Yara-Rules/rules - Repository of yara rules](https://github.com/Yara-Rules/rules)
* [countercept/doublepulsar-detection-script - A python2 script for sweeping a network to find windows systems compromised with the DOUBLEPULSAR implant](https://github.com/countercept/doublepulsar-detection-script)

Online scanners

* Virus scanner
  * [VirusTotal - Analyze suspicious files and URLs to detect types of malware, ](https://www.virustotal.com/#/home/upload)
    * [TheSecondSun/VTSCAN - VirusTotal API script](https://github.com/TheSecondSun/VTSCAN)
  * [NoDistribute - Online Virus Scanner Without Result Distribution](https://nodistribute.com/)
  * [VirSCAN.org - 多引擎在线病毒扫描网](http://www.virscan.org/language/zh-cn/)
* Behavior analysis  
  * [any.run - Interactive malware hunting service](https://app.any.run/)
  * [hybrid-analysis - Free Automated Malware Analysis Service powered by Falcon Sandbox](https://www.hybrid-analysis.com/)
  * [Free Automated Malware Analysis Service - powered by Falcon Sandbox](https://www.reverse.it/)
* Packet analysis
  * [PacketTotal - A free, online PCAP analysis engine](https://www.packettotal.com/)
* APK
  * [Koodous](https://koodous.com/)  
  * [NVISO ApkScan](https://apkscan.nviso.be/)
* Office
  * [Office document malware analysis](https://quicksand.io/)
* Automation
  * [diogo-fernan/malsub - A Python RESTful API framework for online malware analysis and threat intelligence services](https://github.com/diogo-fernan/malsub)

URL security

* [afilipovich/gglsbl - Python client library for Google Safe Browsing API](https://github.com/afilipovich/gglsbl)

Automated analysis

* [certsocietegenerale/fame - FAME Automates Malware Evaluation 有界面](https://github.com/certsocietegenerale/fame)
* [Rurik/Noriben - Noriben - Portable, Simple, Malware Analysis Sandbox](https://github.com/Rurik/Noriben)
* [maliceio/malice - VirusTotal Wanna Be - Now with 100% more Hipster - 类似VT的静态扫描工具，Docker实现，用处不大](https://github.com/maliceio/malice)
* [ashemery/CuckooVM - Cuckoo running in a nested hypervisor](https://github.com/ashemery/CuckooVM)
* [mnrkbys/norimaci - a simple and lightweight malware analysis sandbox for macOS](https://github.com/mnrkbys/norimaci)
* [danieluhricek/LiSa - Sandbox for automated Linux malware analysis](https://github.com/danieluhricek/LiSa)
* MacOS
  * [mac-a-mal](https://github.com/phdphuc/mac-a-mal)
* Javascript
  * [CapacitorSet/box-js - A tool for studying JavaScript malware](https://github.com/CapacitorSet/box-js)
* VM enhancements
  * [nsmfoo/antivmdetection - Script to create templates to use with VirtualBox to make vm detection harder](https://github.com/nsmfoo/antivmdetection)
  * Useful posts
    * [Knowledge Fragment: Hardening Win7 x64 on VirtualBox for Malware Analysis](https://byte-atlas.blogspot.com/2017/02/hardening-vbox-win7x64.html)

Windows

* [countercept/ppid-spoofing - Scripts for performing and detecting parent PID spoofing - 基于ETW的，不确定是否会有误报](https://github.com/countercept/ppid-spoofing)
* [hzqst/Syscall-Monitor - a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+](https://github.com/hzqst/Syscall-Monitor)
* [D4stiny/PeaceMaker - a Windows kernel-based application that detects advanced techniques used by malware - 主要是进程相关，比如设置父进程、线程注入等等，应该误报比较多](https://github.com/D4stiny/PeaceMaker)
* [google/ukip - USB Keystroke Injection Protection](https://github.com/google/ukip)
* [ION28/BLUESPAWN - An Active Defense and EDR software to empower Blue Teams](https://github.com/ION28/BLUESPAWN)
* [matt2005/InjectionHunter - 貌似是检测 powershell 注入的](https://github.com/matt2005/InjectionHunter)
* [glinares/CSCGuard - Protects and logs suspicious and malicious usage of .NET CSC.exe and Runtime C# Compilation](https://github.com/glinares/CSCGuard)
* Active directory
  * [0Kee-Team/WatchAD - AD Security Intrusion Detection System - ATA开源替代，说是360内部用了半年了，没啥误报](https://github.com/0Kee-Team/WatchAD)
  * [kurtfalde/DNS-Debug - Script to enabled DNS Debug Logging across Domain Controllers in a Forest and then retrieve for analysis](https://github.com/kurtfalde/DNS-Debug)
  * [cyberark/zBang - a risk assessment tool that detects potential privileged account threats - 识别SIDHistory、RiskySPN、kerberos delegation等问题](https://github.com/cyberark/zBang)
  * [vletoux/pingcastle - Get Active Directory Security at 80% in 20% of the time](https://github.com/vletoux/pingcastle)
  * [phillips321/adaudit - Powershell script to do domain auditing automation](https://github.com/phillips321/adaudit)
  * [shellster/DCSYNCMonitor - Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events](https://github.com/shellster/DCSYNCMonitor)
  * [sisoc-tokyo/Real-timeDetectionAD_ver2 - a real-time detection tool for detecting attack against Active Directory](https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2)
  * [lazywinadmin/Monitor-ADGroupMembership - PowerShell script to monitor Active Directory groups and send an email when someone is changing the membership](https://github.com/lazywinadmin/Monitor-ADGroupMembership)
  * [cyberark/ketshash - A little tool for detecting suspicious privileged NTLM connections, in particular Pass-The-Hash attack, based on event viewer logs](https://github.com/cyberark/ketshash)
* WEF
  * [palantir/windows-event-forwarding - A repository for using windows event forwarding for incident detection and response](https://github.com/palantir/windows-event-forwarding)
  * [Windows Event Forwarding for Network Defense](https://medium.com/@palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
  * [iadgov/Event-Forwarding-Guidance - Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding. iadgov](https://github.com/iadgov/Event-Forwarding-Guidance)
* Spoofing detection
  * [joda32/got-responded - A simple tool to detect NBT-NS and LLMNR spoofing (and messing with them a bit)](https://github.com/joda32/got-responded)

Linux

* Rootkit detection
  * [David-Reguera-Garcia-Dreg/lsrootkit - via GID bruteforcing](https://github.com/David-Reguera-Garcia-Dreg/lsrootkit)
  * [nbulischeck/tyton - Kernel-Mode Rootkit Hunter - 只支持4.X内核，好用](https://github.com/nbulischeck/tyton)
* Auditd
  * [linux-audit/audit-userspace/rules - auditd 一些规则，稍微有点用](https://github.com/linux-audit/audit-userspace/tree/master/rules)
  * [Neo23x0/auditd - Best Practice Auditd Configuration - 过滤规则很有价值](https://github.com/Neo23x0/auditd)
  * [bfuzzy/auditd-attack - A Linux Auditd rule set mapped to MITRE's Attack Framework](https://github.com/bfuzzy/auditd-attack)

Mac

* [objective-see/ReiKey - Malware and other applications may install persistent keyboard "event taps" to intercept your keystrokes. ReiKey can scan, detect, and monitor for such taps!](https://github.com/objective-see/ReiKey)
* [SuprHackerSteve/Crescendo - a swift based, real time event viewer for macOS. It utilizes Apple's Endpoint Security Framework](https://github.com/SuprHackerSteve/Crescendo)

Detect obfuscation

* [We5ter/Flerken - Open-Source Obfuscated Command Detection Tool](https://github.com/We5ter/Flerken)

Traffic analysis

* [dirtbags/pcapdb - A Distributed, Search-Optimized Full Packet Capture System](https://github.com/dirtbags/pcapdb)
* [TravisFSmith/SweetSecurity - Network Security Monitoring on Raspberry Pi type devices](https://github.com/TravisFSmith/SweetSecurity)
* [noddos - Noddos client](https://github.com/noddos/noddos)
* [Suricata - a free and open source, mature, fast and robust network threat detection engine](https://suricata-ids.org/)
* [aol/moloch - Moloch is an open source, large scale, full packet capturing, indexing, and database system](https://github.com/aol/moloch)
* [stamparm/maltrail - Malicious traffic detection system](https://github.com/stamparm/maltrail)
* [360PegasusTeam/WiFi-Miner-Detector - Detecting malicious WiFi with mining cryptocurrency](https://github.com/360PegasusTeam/WiFi-Miner-Detector)
* [activecm/rita - Real Intelligence Threat Analytics](https://github.com/activecm/rita)
* [zeek - A powerful framework for network traffic analysis and security monitoring.](https://github.com/zeek/zeek)
* [StamusNetworks/SELKS - A Suricata based IDS/IPS distro](https://github.com/StamusNetworks/SELKS)
* [ptresearch/AttackDetection - Suricata PT Open Ruleset](https://github.com/ptresearch/AttackDetection)

Network

* [codeexpress/respounder - detects presence of responder in the network](https://github.com/codeexpress/respounder)
* [europa502/shARP - An anti-ARP-spoofing application software that use active and passive scanning methods to detect and remove any ARP-spoofer from the network](https://github.com/europa502/shARP)
* Email
  * [CIRCL/IMAP-Proxy - Modular IMAP proxy (including PyCIRCLeanMail and MISP forward modules)](https://github.com/CIRCL/IMAP-Proxy)

Monitoring

* [realparisi/WMI_Monitor - Log newly created WMI consumers and processes](https://github.com/realparisi/WMI_Monitor)
* [luctalpe/WMIMon - Tool to monitor WMI activity on Windows](https://github.com/luctalpe/WMIMon)
* [9b/chirp - Interface to manage and centralize Google Alert information](https://github.com/9b/chirp)
* [facebook/osquery - SQL powered operating system instrumentation, monitoring, and analytics](https://github.com/facebook/osquery)
  * [BlueHat v17 || Detecting Compromise on Windows Endpoints with Osquery](https://www.slideshare.net/MSbluehat/bluehat-v17-detecting-compromise-on-windows-endpoints-with-osquery-84024735)
  * [osql/extensions - osql community extensions](https://github.com/osql/extensions)
  * [clong/detect-responder - Detect Responder (LLMNR, NBT-NS, MDNS poisoner) with osquery](https://github.com/clong/detect-responder)
  * [kolide/fleet - A flexible control server for osquery fleets](https://github.com/kolide/fleet)
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

Signature tools

* [mattifestation/file-getpefeature-ps1 - Retrieves key features from PE files that can be used to build detections](https://gist.github.com/mattifestation/3dc9ece6ee04be62ec8df16bf1047436#file-getpefeature-ps1)
* Yara tools / rules
  * [CERT-Polska/mquery - YARA malware query accelerator (web frontend)](https://github.com/CERT-Polska/mquery)
  * [botherder/kraken - Cross-platform Yara scanner written in Go](https://github.com/botherder/kraken)
  * [Neo23x0/yarGen - a generator for YARA rules](https://github.com/Neo23x0/yarGen)
  * [InQuest/yara-rules - A collection of YARA rules we wish to share with the world](https://github.com/InQuest/yara-rules)
  * [Neo23x0/panopticon - A YARA Rule Performance Measurement Tool](https://github.com/Neo23x0/panopticon)

Sandbox analysis

* [phdphuc/mac-a-mal-cuckoo - This analyzer extends the open-source Cuckoo Sandbox (legacy) with functionality for analyzing macOS malware in macOS guest VM(s)](https://github.com/phdphuc/mac-a-mal-cuckoo)
* [cuckoo-install.sh - Cuckoo auto installer for Ubuntu](https://github.com/NVISO-BE/SEC599/blob/master/cuckoo-install.sh)
* [CERT-Polska/drakvuf-sandbox - DRAKVUF Sandbox - automated hypervisor-level malware analysis system](https://github.com/CERT-Polska/drakvuf-sandbox)
* [blacktop/docker-cuckoo - Cuckoo Sandbox Dockerfile](https://github.com/blacktop/docker-cuckoo)

Security intelligence / feeds

* [TheHive-Project/Hippocampe - Threat Feed Aggregation, Made Easy](https://github.com/TheHive-Project/Hippocampe)
* [MISP - Open Source Threat Intelligence Platform (formely known as Malware Information Sharing Platform)](https://github.com/MISP/MISP)

Uncategorized

* [christophetd/hunting-mindmaps - Mindmaps for threat hunting - WIP](https://github.com/christophetd/hunting-mindmaps)
* [microsoft/msticpy - Microsoft Threat Intelligence Security Tools](https://github.com/microsoft/msticpy)
* [target/strelka - a real-time file scanning system used for threat hunting, threat detection, and incident response](https://github.com/target/strelka)
* [phishai/phish-protect - Chrome extension to alert and possibly block IDN/Unicode websites and zero-day phishing websites using AI and Computer Vision](https://github.com/phishai/phish-protect)
* [Cyb3rWard0g/HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
   * [toolsmith #131 - The HELK vs APTSimulator - Part 1](https://holisticinfosec.blogspot.com.au/2018/02/toolsmith-131-helk-vs-aptsimulator-part.html)
* [endgameinc/ClrGuard - a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes - AppInit注入DLL，然后检测CLR加载事件](https://github.com/endgameinc/ClrGuard)
* [ION28/BLUESPAWN - Windows-based Active Defense and EDR tool to empower Blue Teams](https://github.com/ION28/BLUESPAWN)

## Resources / Training materials

* [A source for pcap files and malware samples](http://www.malware-traffic-analysis.net/)
* [workshop: RESOLVN/RTHVM - The Resolvn Threat Hunting Virtual Machine (RTHVM) is a training resource used during a 2019 Packet Hacking Village workshop titled Intel-driven Hunts for Nation-state Activity Using Elastic SIEM - 介绍了多个日志查询案例，比如存活较短的计划任务](https://github.com/RESOLVN/RTHVM)

## Tutorials

Uncategorized

* [Tales of a Threat Hunter 2 - Following the trace of WMI Backdoors & other nastiness](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [awslabs/aws-security-automation - Collection of scripts and resources for DevSecOps and Automated Incident Response Security](https://github.com/awslabs/aws-security-automation)
* [mitre/attack-navigator - Web app that provides basic navigation and annotation of ATT&CK matrices](https://github.com/mitre/attack-navigator)
* [Establishing a Baseline for Remote Desktop Protocol](https://www.fireeye.com/blog/threat-research/2018/04/establishing-a-baseline-for-remote-desktop-protocol.html)
* [Disrupting the Empire: Identifying PowerShell Empire Command and Control Activity](https://www.sans.org/reading-room/whitepapers/incident/disrupting-empire-identifying-powershell-empire-command-control-activity-38315)
* [OffensiveSplunk vs. Grep](https://vincentyiu.co.uk/offensivesplunk/)
* [speakerdeck: Hunting for Privilege Escalation in Windows Environment - 使用sysmon+ELK检测各种提权](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
* [AWS Security Incident Response](https://d1.awsstatic.com/whitepapers/aws_security_incident_response.pdf)
* [speakerdeck: Hunting for Privilege Escalation in Windows Environment - 根据日志分析提权，没有实际的大规模应用例子，只是留个记录](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)

Books

* [OWASP - Automated Threat Handbook - Web Applications](https://www.owasp.org/images/3/33/Automated-threat-handbook.pdf)

Frameworks

* [palantir/alerting-detection-strategy-framework - A framework for developing alerting and detection strategies for incident response](https://github.com/palantir/alerting-detection-strategy-framework)

Auditing

* [WINDOWS REGISTRY AUDITING CHEAT SHEET - Win 7/Win 2008 or later](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows)
* [WINDOWS ATT&CK LOGGING CHEAT SHEET - Win 7 - Win 2012 - ATT&CK模型，以及对应的日志编号，很有用](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5b8f091c0ebbe8644d3a886c/1536100639356/Windows+ATT&CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf)
* [WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf)
* [Public_Windows Event Log Zero 2 Hero Slides - 常见恶意行为日志说明，搜索语句以及识别方法](https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit#slide=id.g21acf94f3f_2_27)

Database 

* [slideshare: Database Firewall from Scratch](https://www.slideshare.net/dnkolegov/database-firewall-from-scratch-76281350)



