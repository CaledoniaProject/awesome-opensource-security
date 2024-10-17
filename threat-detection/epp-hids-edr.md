# HIDS & EDR

Evaluation

* [EDR Internals for macOS and Linux](https://www.outflank.nl/blog/2024/06/03/edr-internals-macos-linux/)
* [tsale/EDR-Telemetry - This project aims to compare and evaluate the telemetry of various EDR products](https://github.com/tsale/EDR-Telemetry)
* [Endpoint Prevention & Response (EPR) Test 2022 - AVComparatives每年10月份发布一次报告，可以从 https://zc.vg/sf/jYbKz 订阅他们的新闻](https://www.av-comparatives.org/endpoint-prevention-response-epr-test-2022/)

EDR - Linux

* eBPF based
  * [elastic/ebpf - This repository contains eBPF code as well as associated userspace tools and components used in the Linux build of Elastic Endpoint Security](https://github.com/elastic/ebpf)
  * [redcanaryco/redcanary-ebpf-sensor - Red Canary's eBPF Sensor](https://github.com/redcanaryco/redcanary-ebpf-sensor)
  * [falcosecurity/falco - Container Native Runtime Security](https://github.com/falcosecurity/falco)
    * https://falco.org/blog/intro-gvisor-falco/
  * [aquasecurity/tracee - Container and system event tracing using eBPF](https://github.com/aquasecurity/tracee)
  * [Sysinternals/SysmonForLinux - 官方基于eBPF的Linux实现](https://github.com/Sysinternals/SysmonForLinux)
  * [cilium - eBPF-based Networking, Security, and Observability - 9.4K star](https://github.com/cilium/cilium)
  * [cilium/tetragon - eBPF-based Security Observability and Runtime Enforcement](https://github.com/cilium/tetragon)
    * [Tetragon进程阻断原理](https://mp.weixin.qq.com/s/BT1efaHicwqHWrwDtT_f5w)
* [a2o/snoopy - Snoopy Command Logger is a small library that logs all program executions on your Linux/BSD system - 基于LD_PRELOAD实现的，1.1K star](https://github.com/a2o/snoopy)
* [bytedance/Elkeid - a Cloud-Native Host-Based Intrusion Detection solution project to provide next-generation Threat Detection and Behavior Audition with modern architecture](https://github.com/bytedance/Elkeid)
* [wazuh - Host and endpoint security](https://github.com/wazuh/wazuh)
* [ysrc/yulong-hids - 一款由 YSRC 开源的主机入侵检测系统 - 2020停更](https://github.com/ysrc/yulong-hids)
* [linux-malware-detect - 纯规则，没啥用，严格来说就是个杀毒](https://www.rfxn.com/projects/linux-malware-detect/)

EDR - Windows

* [amjcyber/EDRNoiseMaker - Detect WFP filters blocking EDR communications](https://github.com/amjcyber/EDRNoiseMaker)
* [Xacone/BestEdrOfTheMarket - Little AV/EDR bypassing lab for training & learning purposes](https://github.com/Xacone/BestEdrOfTheMarket)
* [ION28/BLUESPAWN - An Active Defense and EDR software to empower Blue Teams - 1K star](https://github.com/ION28/BLUESPAWN)
* [wecooperate/iMonitor - iMonitor（冰镜 - 终端行为分析系统）](https://github.com/wecooperate/iMonitor)
* [ComodoSecurity/openedr - Open EDR public repository - 1.3K star](https://github.com/ComodoSecurity/openedr)
* [Invoke-IR/Uproot - a Host Based Intrusion Detection System (HIDS) that leverages Permanent Windows Management Instrumentation (WMI) Event Susbcriptions to detect malicious activity on a network, 2016年停止更新](https://github.com/Invoke-IR/Uproot)

EDR - Mac

* [redcanaryco/mac-monitor - Red Canary Mac Monitor is an advanced, stand-alone system monitoring tool tailor-made for macOS security research. Beginning with Endpoint Security (ES), it collects and enriches system events, displaying them graphically, with an expansive feature set designed to reduce noise](https://github.com/redcanaryco/mac-monitor)

Uncategorized

* [jaredcatkinson/Get-InjectedThread.ps1 - Looks for threads that were created as a result of code injection](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
  * [Understanding and Evading Get-InjectedThread](https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/)
* [TonyPhipps/THRecon - Collect endpoint information for use in incident response triage / threat hunting / live forensics using this toolkit](https://github.com/TonyPhipps/THRecon)
* [Neo23x0/Fenrir - Simple Bash IOC Scanner](https://github.com/Neo23x0/Fenrir)
* [mvelazc0/Oriana - a threat hunting tool that leverages a subset of Windows events to build relationships, calculate totals and run analytics](https://github.com/mvelazc0/Oriana/)
* [pmsosa/duckhunt - Prevent RubberDucky (or other keystroke injection) attacks](https://github.com/pmsosa/duckhunt)
* [momosecurity/cornerstone - Linux命令转发记录 - 基于 bashrc 的，绕过方式太多，不过还是留个记录](https://github.com/momosecurity/cornerstone)
* [grayddq/GScan - 本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧Checklist的自动全面化检测 - 传说中的鸡肋工具](https://github.com/grayddq/GScan)
* [crowdsecurity/crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database](https://github.com/crowdsecurity/crowdsec/)

# Resources

* [Ghost Wolf Lab - Evasions](https://evasions.ghostwolflab.com/)
* [XDR detection engineering at scale: crafting detection rules for SecOps efficiency](https://blog.sekoia.io/xdr-detection-rules-at-scale/)
