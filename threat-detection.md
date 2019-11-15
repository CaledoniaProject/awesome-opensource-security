# opensource-threat-detection

A collection of open source threat detection tools

## Collections

3rd-party lists

* [MHaggis/hunt-detect-prevent - Lists of sources and utilities utilized to hunt, detect and prevent evildoers](https://github.com/MHaggis/hunt-detect-prevent)
* [0x4D31/awesome-threat-detection - A curated list of awesome threat detection and hunting resources](https://github.com/0x4D31/awesome-threat-detection)
* [olafhartong/detection-sources - a linkdump with locations to find great new idea's for developing detection content](https://github.com/olafhartong/detection-sources)
* [infosecn1nja/awesome-mitre-attack - Awesome Mitre ATT&CK™ Framework](https://github.com/infosecn1nja/awesome-mitre-attack)

Online scanners

* Virus scanner
  * [VirusTotal - Analyze suspicious files and URLs to detect types of malware, ](https://www.virustotal.com/#/home/upload)
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

Automated analysis

* [certsocietegenerale/fame - FAME Automates Malware Evaluation 有界面](https://github.com/certsocietegenerale/fame)
* [Rurik/Noriben - Noriben - Portable, Simple, Malware Analysis Sandbox](https://github.com/Rurik/Noriben)
* [maliceio/malice - VirusTotal Wanna Be - Now with 100% more Hipster - 类似VT的静态扫描工具，Docker实现，用处不大](https://github.com/maliceio/malice)
* MacOS
  * [mac-a-mal](https://github.com/phdphuc/mac-a-mal)
* Javascript
  * [CapacitorSet/box-js - A tool for studying JavaScript malware](https://github.com/CapacitorSet/box-js)
* VM enhancements
  * [nsmfoo/antivmdetection - Script to create templates to use with VirtualBox to make vm detection harder](https://github.com/nsmfoo/antivmdetection)
  * Useful posts
    * [Knowledge Fragment: Hardening Win7 x64 on VirtualBox for Malware Analysis](https://byte-atlas.blogspot.com/2017/02/hardening-vbox-win7x64.html)

Windows

* [AxtMueller/Windows-Kernel-Explorer - A free but powerful Windows kernel research tool](https://github.com/AxtMueller/Windows-Kernel-Explorer)
* Active domain
  * [0Kee-Team/WatchAD - AD Security Intrusion Detection System - ATA开源替代，说是360内部用了半年了，没啥误报](https://github.com/0Kee-Team/WatchAD)
* Event Tracing for Windows (ETW)
  * [chentiangemalc/EtlToCap - Convert ETL to PCAP](https://github.com/chentiangemalc/EtlToCap)
  * [chentiangemalc/PowerShellScripts - ConvertEtl-ToPcap.ps1](https://github.com/chentiangemalc/PowerShellScripts/blob/master/ConvertEtl-ToPcap.ps1)
  * [fireeye/SilkETW - a flexible C# wrapper for ETW, it is meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection](https://github.com/fireeye/SilkETW)
  * [google/UIforETW - User interface for recording and managing ETW traces](https://github.com/google/UIforETW)
* Active directory
  * [kurtfalde/DNS-Debug - Script to enabled DNS Debug Logging across Domain Controllers in a Forest and then retrieve for analysis](https://github.com/kurtfalde/DNS-Debug)
  * [cyberark/zBang - a risk assessment tool that detects potential privileged account threats - 识别SIDHistory、RiskySPN、kerberos delegation等问题](https://github.com/cyberark/zBang)
  * [vletoux/pingcastle - Get Active Directory Security at 80% in 20% of the time](https://github.com/vletoux/pingcastle)
  * [phillips321/adaudit - Powershell script to do domain auditing automation](https://github.com/phillips321/adaudit)
  * [shellster/DCSYNCMonitor - Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events](https://github.com/shellster/DCSYNCMonitor)
  * [sisoc-tokyo/Real-timeDetectionAD_ver2 - a real-time detection tool for detecting attack against Active Directory](https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2)
* Windows Event forwarding  
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

Mac

* [objective-see/ReiKey - Malware and other applications may install persistent keyboard "event taps" to intercept your keystrokes. ReiKey can scan, detect, and monitor for such taps!](https://github.com/objective-see/ReiKey)

Risk Control

* [threathunterX/nebula - 星云风控系统是一套互联网风控分析和检测平台，可以对企业遇到的各种业务风险场景进行细致的分析，找出威胁流量，帮助用户减少损失](https://github.com/threathunterX/nebula)

Detect obfuscation

* [We5ter/Flerken - Open-Source Obfuscated Command Detection Tool](https://github.com/We5ter/Flerken)

Browser

* [1lastBr3ath/drmine - Dr. Mine is a node script written to aid automatic detection of in-browser cryptojacking](https://github.com/1lastBr3ath/drmine)
* [leizongmin/js-xss - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist](https://github.com/leizongmin/js-xss)

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

Network

* [europa502/shARP - An anti-ARP-spoofing application software that use active and passive scanning methods to detect and remove any ARP-spoofer from the network](https://github.com/europa502/shARP)
* Email
  * [CIRCL/IMAP-Proxy - Modular IMAP proxy (including PyCIRCLeanMail and MISP forward modules)](https://github.com/CIRCL/IMAP-Proxy)

Host based detection tools / endpoint tools

* [jaredcatkinson/Get-InjectedThread.ps1 - Looks for threads that were created as a result of code injection](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
  * [Understanding and Evading Get-InjectedThread](https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/)
* [TonyPhipps/THRecon - Collect endpoint information for use in incident response triage / threat hunting / live forensics using this toolkit](https://github.com/TonyPhipps/THRecon)
* [Neo23x0/Fenrir - Simple Bash IOC Scanner](https://github.com/Neo23x0/Fenrir)
* [0x4D31/salt-scanner - Linux vulnerability scanner based on Salt Open and Vulners audit API, with Slack notifications and JIRA integration](https://github.com/0x4D31/salt-scanner)
* [DominicBreuker/pspy - Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy)
* [mvelazc0/Oriana - a threat hunting tool that leverages a subset of Windows events to build relationships, calculate totals and run analytics](https://github.com/mvelazc0/Oriana/)
* [Hestat/minerchk - Bash script to Check for malicious Cryptomining](https://github.com/Hestat/minerchk)
* [pmsosa/duckhunt - Prevent RubberDucky (or other keystroke injection) attacks](https://github.com/pmsosa/duckhunt)
* [momosecurity/cornerstone - Linux命令转发记录 - 基于 bashrc 的，绕过方式太多，不过还是留个记录](https://github.com/momosecurity/cornerstone)
* [grayddq/GScan - 本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧Checklist的自动全面化检测 - 传说中的鸡肋工具](https://github.com/grayddq/GScan)
* HIDS
  * [Invoke-IR/Uproot - a Host Based Intrusion Detection System (HIDS) that leverages Permanent Windows Management Instrumentation (WMI) Event Susbcriptions to detect malicious activity on a network, 2016年停止更新](https://github.com/Invoke-IR/Uproot)
  * [ysrc/yulong-hids - 一款由 YSRC 开源的主机入侵检测系统](https://github.com/ysrc/yulong-hids)
* Memory analysis
  * [DamonMohammadbagher/Meterpreter_Payload_Detection - for detecting Meterpreter in memory like IPS-IDS and Forensics tool](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)
* Active directory
  * [shellster/DCSYNCMonitor - Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events](https://github.com/shellster/DCSYNCMonitor)
  * [AlsidOfficial/UncoverDCShadow - A PowerShell utility to dynamically uncover a DCShadow attack](https://github.com/AlsidOfficial/UncoverDCShadow)

Sysmon

* [marcosd4h/sysmonx - An Augmented Drop-In Replacement of Sysmon](https://github.com/marcosd4h/sysmonx)
* [JPCERTCC/SysmonSearch - Investigate suspicious activity by visualizing Sysmon's event log](https://github.com/JPCERTCC/SysmonSearch)
* [darkoperator/Posh-Sysmon - PowerShell module for creating and managing Sysinternals Sysmon config files](https://github.com/darkoperator/Posh-Sysmon)
* [mattifestation/PSSysmonTools - Sysmon Tools for PowerShell - SysmonRuleParser.ps1 可以列出本机sysmon的配置](https://github.com/mattifestation/PSSysmonTools)
* [olafhartong/sysmon-cheatsheet - All sysmon event types and their fields explained](https://github.com/olafhartong/sysmon-cheatsheet)
* [matterpreter/Shhmon - Neutering Sysmon via driver unload](https://github.com/matterpreter/Shhmon)
* Rules
  * [SwiftOnSecurity/sysmon-config - Sysmon configuration file template with default high-quality event tracing](https://github.com/SwiftOnSecurity/sysmon-config)
  * [olafhartong/sysmon-modular - A repository of sysmon configuration modules](https://github.com/olafhartong/sysmon-modular)
  * [Neo23x0/sigma - rules/windows/sysmon](https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon)
  * [0xpwntester/Sysmon - Sysmon configuration and scripts](https://github.com/0xpwntester/Sysmon)
  * [sbousseaden/Panache_Sysmon - A Sysmon Config for APTs Techniques Detection](https://github.com/sbousseaden/Panache_Sysmon)
* Researches
  * [mattifestation/BHUSA2018_Sysmon - All materials from our Black Hat 2018 "Subverting Sysmon" talk](https://github.com/mattifestation/BHUSA2018_Sysmon)

Webshell detection

* [baidu-security/webshell-scanner-client - A golang client of https://scanner.baidu.com](https://github.com/baidu-security/webshell-scanner-client)
* [nbs-system/php-malware-finder - Detect potentially malicious PHP files](https://github.com/nbs-system/php-malware-finder)
* [emposha/PHP-Shell-Detector - a php script that helps you find and identify php/cgi(perl)/asp/aspx shells](https://github.com/emposha/PHP-Shell-Detector)
* [chaitin/cloudwalker - Webshell 查杀](https://github.com/chaitin/cloudwalker)

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
* Github
  * [FeeiCN/GSIL - GitHub Sensitive Information Leakage（GitHub敏感信息泄露监控）](https://github.com/FeeiCN/GSIL)
  * [MiSecurity/x-patrol - github泄露扫描系统](https://github.com/MiSecurity/x-patrol)
  * [neal1991/gshark - Scan for sensitive information in Github easily and effectively](https://github.com/neal1991/gshark)
  * [0xbug/Hawkeye - GitHub 泄露监控系统 - 有界面，star 很多](https://github.com/0xbug/Hawkeye)
* Zabbix plugin
  * [vulnersCom/zabbix-threat-control - Zabbix vulnerability assessment plugin](https://github.com/vulnersCom/zabbix-threat-control)
* ElasticSearch addons
  * [NVISO-BE/ee-outliers - Open-source framework to detect outliers in Elasticsearch events](https://github.com/NVISO-BE/ee-outliers)

Log analysis / Visualization

* [Scribery/tlog - Terminal I/O logger](https://github.com/Scribery/tlog)
  * [USER SESSION RECORDING - An Open Source solution](https://ruxcon.org.au/assets/2017/slides/Session%20Recording%20Ruxcon%202017.pdf)
* [JPCERTCC/LogonTracer - Investigate malicious Windows logon by visualizing and analyzing Windows event log](https://github.com/JPCERTCC/LogonTracer)
* [THIBER-ORG/userline - Query and report user logons relations from MS Windows Security Events](https://github.com/THIBER-ORG/userline)
* [austin-taylor/VulnWhisperer - Create actionable data from your Vulnerability Scans](https://github.com/austin-taylor/VulnWhisperer)
* [Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)

Log queries

* [beahunt3r/Windows-Hunting - Aid windows threat hunters to look for some common artifacts during their day to day operations](https://github.com/beahunt3r/Windows-Hunting)
* [Microsoft/WindowsDefenderATP-Hunting-Queries - Sample queries for Advanced hunting in Windows Defender ATP](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries/)
* [Hunting for reconnaissance activities using LDAP search filters - Metasploit/Powerview/Bloudhound的LDAP查询是有特征的](https://techcommunity.microsoft.com/t5/Microsoft-Defender-ATP/Hunting-for-reconnaissance-activities-using-LDAP-search-filters/ba-p/824726)
* [BlueTeamLabs/sentinel-attack - Repository of sentinel alerts and hunting queries leveraging sysmon and the MITRE ATT&CK framework](https://github.com/BlueTeamLabs/sentinel-attack)
* [sbousseaden/Slides - Summarized Overview of different hunting paths an Analyst can take per EventId or technique](https://github.com/sbousseaden/Slides)

SIEM

* [TheHive-Project/TheHive - TheHive: a Scalable, Open Source and Free Security Incident Response Platform](https://github.com/TheHive-Project/TheHive)
* [wazuh - Host and endpoint security](https://github.com/wazuh/wazuh)
* [uncoder.io - SOC Prime - 转换SIEM查询语句的工具](https://uncoder.io/#)

Signature tools

* [mattifestation/file-getpefeature-ps1 - Retrieves key features from PE files that can be used to build detections](https://gist.github.com/mattifestation/3dc9ece6ee04be62ec8df16bf1047436#file-getpefeature-ps1)
* Yara tools / rules
  * [CERT-Polska/mquery - YARA malware query accelerator (web frontend)](https://github.com/CERT-Polska/mquery)
  * [botherder/kraken - Cross-platform Yara scanner written in Go](https://github.com/botherder/kraken)
  * [Neo23x0/yarGen - a generator for YARA rules](https://github.com/Neo23x0/yarGen)
  * [InQuest/yara-rules - A collection of YARA rules we wish to share with the world](https://github.com/InQuest/yara-rules)

Sandbox analysis

* [phdphuc/mac-a-mal-cuckoo - This analyzer extends the open-source Cuckoo Sandbox (legacy) with functionality for analyzing macOS malware in macOS guest VM(s)](https://github.com/phdphuc/mac-a-mal-cuckoo)
* [cuckoo-install.sh - Cuckoo auto installer for Ubuntu](https://github.com/NVISO-BE/SEC599/blob/master/cuckoo-install.sh)

Phishing

* [wesleyraptor/streamingphish - Python-based utility that uses supervised machine learning to detect phishing domains from the Certificate Transparency log network](https://github.com/wesleyraptor/streamingphish)
* [OpenPhish - Phishing Intelligence](https://openphish.com/)
* [x0rz/phishing_catcher - Phishing catcher using Certstream](https://github.com/x0rz/phishing_catcher)

Security intelligence / feeds

* [TheHive-Project/Hippocampe - Threat Feed Aggregation, Made Easy](https://github.com/TheHive-Project/Hippocampe)
* [MISP - Open Source Threat Intelligence Platform (formely known as Malware Information Sharing Platform)](https://github.com/MISP/MISP)

Uncategorized

* [microsoft/msticpy - Microsoft Threat Intelligence Security Tools](https://github.com/microsoft/msticpy)
* [target/strelka - a real-time file scanning system used for threat hunting, threat detection, and incident response](https://github.com/target/strelka)
* [phishai/phish-protect - Chrome extension to alert and possibly block IDN/Unicode websites and zero-day phishing websites using AI and Computer Vision](https://github.com/phishai/phish-protect)
* [Cyb3rWard0g/HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
   * [toolsmith #131 - The HELK vs APTSimulator - Part 1](https://holisticinfosec.blogspot.com.au/2018/02/toolsmith-131-helk-vs-aptsimulator-part.html)
* [endgameinc/ClrGuard - a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes - CLR动态加载检测](https://github.com/endgameinc/ClrGuard)
* [ION28/BLUESPAWN - Windows-based Active Defense and EDR tool to empower Blue Teams](https://github.com/ION28/BLUESPAWN)

## Attack Simulation

Tools

* [redhuntlabs/RedHunt-OS - Virtual Machine for Adversary Emulation and Threat Hunting](https://github.com/redhuntlabs/RedHunt-OS)
* [vysec/CACTUSTORCH - Payload Generation for Adversary Simulations](https://github.com/vysec/CACTUSTORCH)
* [NextronSystems/APTSimulator - A toolset to make a system look as if it was the victim of an APT attack](https://github.com/NextronSystems/APTSimulator)
* [redcanaryco/atomic-red-team - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework](https://github.com/redcanaryco/atomic-red-team)
* [mitre/caldera - An automated adversary emulation system](https://github.com/mitre/caldera)
   * [INSTALL/SETUP MITRE CALDERA THE AUTOMATED CYBER ADVERSARY EMULATION SYSTEM](https://holdmybeersecurity.com/2018/01/13/install-setup-mitre-caldera-the-automated-cyber-adversary-emulation-system/)
* [uber-common/metta - An information security preparedness tool to do adversarial simulation](https://github.com/uber-common/metta)
* [endgameinc/RTA - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.](https://github.com/endgameinc/RTA)
* [TryCatchHCF/DumpsterFire - DumpsterFire Toolset - "Security Incidents In A Box!"](https://github.com/TryCatchHCF/DumpsterFire)
* [jymcheong/AutoTTP - Automated Tactics Techniques & Procedures](https://github.com/jymcheong/AutoTTP)
* [Cyb3rWard0g/Invoke-ATTACKAPI - A PowerShell script to interact with the MITRE ATT&CK Framework via its own API](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI)
* [CyberMonitor/Invoke-Adversary - Simulating Adversary Operations](https://github.com/CyberMonitor/Invoke-Adversary)
* [P4T12ICK/ypsilon - an Automated Security Use Case Testing Environment using real malware to test SIEM use cases in an closed environment](https://github.com/P4T12ICK/ypsilon)
* [n0dec/MalwLess - Test Blue Team detections without running any attack](https://github.com/n0dec/MalwLess)
* [Cyb3rWard0g/mordor - Re-play Adversarial Techniques](https://github.com/Cyb3rWard0g/mordor)
* [mvelazc0/PurpleSharp - a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments](https://github.com/mvelazc0/PurpleSharp)

Dataset

* [splunk/botsv1 - Boss of the SOC (BOTS) Dataset Version 1](https://github.com/splunk/botsv1)
* [sbousseaden/EVTX-ATTACK-SAMPLES - Windows Events Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

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



