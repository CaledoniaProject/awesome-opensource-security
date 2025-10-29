Uncategorized

* [marcosd4h/sysmonx - An Augmented Drop-In Replacement of Sysmon](https://github.com/marcosd4h/sysmonx)
* [JPCERTCC/SysmonSearch - Investigate suspicious activity by visualizing Sysmon's event log](https://github.com/JPCERTCC/SysmonSearch)
* [darkoperator/Posh-Sysmon - PowerShell module for creating and managing Sysinternals Sysmon config files](https://github.com/darkoperator/Posh-Sysmon)
* [mattifestation/PSSysmonTools - Sysmon Tools for PowerShell - SysmonRuleParser.ps1 可以列出本机sysmon的配置](https://github.com/mattifestation/PSSysmonTools)
* [olafhartong/sysmon-cheatsheet - All sysmon event types and their fields explained](https://github.com/olafhartong/sysmon-cheatsheet)
* [matterpreter/Shhmon - Neutering Sysmon via driver unload](https://github.com/matterpreter/Shhmon)
* [cudeso/tools/powershell/Sysmon-DNS/passivedns.ps1 - sysmon event 转换为 SQLite](https://github.com/cudeso/tools/blob/master/powershell/Sysmon-DNS/passivedns.ps1)
* [MHaggis/sysmon-dfir - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon](https://github.com/MHaggis/sysmon-dfir)
* [nshalabi/SysmonTools - Utilities for Sysmon](https://github.com/nshalabi/SysmonTools)
* [NtRaiseHardError/Sysmon - Sysmon shenanigans - Sysmon-KExec/ImageFileName-Evasion，高端](https://github.com/NtRaiseHardError/Sysmon)
  * [Sysmon Internals - From File Delete Event to Kernel Code Execution](https://undev.ninja/sysmon-internals-from-file-delete-event-to-kernel-code-execution/)

Rules

* [SwiftOnSecurity/sysmon-config - Sysmon configuration file template with default high-quality event tracing](https://github.com/SwiftOnSecurity/sysmon-config)
* [olafhartong/sysmon-modular - A repository of sysmon configuration modules](https://github.com/olafhartong/sysmon-modular)
* [Neo23x0/sigma - rules/windows/sysmon](https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon)
* [0xpwntester/Sysmon - Sysmon configuration and scripts](https://github.com/0xpwntester/Sysmon)
* [gavz/Panache_Sysmon - A Sysmon Config for APTs Techniques Detection](https://github.com/gavz/Panache_Sysmon)
* [Hestat/ossec-sysmon - A Ruleset to enhance detection capabilities of Ossec using Sysmon](https://github.com/Hestat/ossec-sysmon)

Evasion

* [codewhitesec/SysmonEnte - This is a POC attack on the integrity of Sysmon which emits a minimal amount of observable events even if a SACL is in place - hook方式过滤事件](https://github.com/codewhitesec/SysmonEnte)
* [mattifestation/BHUSA2018_Sysmon - Slides_Subverting_Sysmon.pdf - WMI缺少root/default的监控；网上公开规则只看文件名，容易绕过；注入监控少APC的](https://github.com/mattifestation/BHUSA2018_Sysmon/blob/master/Slides_Subverting_Sysmon.pdf)
* [SecurityJosh/MuteSysmon - A PowerShell script to prevent Sysmon from writing its events - 实战不会用到，仅保留作为参考。通过删除manifest或者修改注册表权限，是sysmon无法工作](https://github.com/SecurityJosh/MuteSysmon)
* [bats3c/EvtMute - 挂钩wevtsvc.dll的ETW回调，然后用yara去匹配PEVENT_RECORD来过滤。定位回调函数的方法不可靠，仅作为一个参考保留](https://github.com/bats3c/EvtMute)

Researches

* [mattifestation/BHUSA2018_Sysmon - All materials from our Black Hat 2018 "Subverting Sysmon" talk](https://github.com/mattifestation/BHUSA2018_Sysmon)

Guides

* [Hunting and detecting APTs using Sysmon and PowerShell logging - botconf2018](https://www.botconf.eu/wp-content/uploads/formidable/2/2018-Tom-Ueltschi-Sysmon.pdf)
* [Sysmon原理逆向探究](https://mp.weixin.qq.com/s/gj4c0lBalPf_fA82RvFI5w)
