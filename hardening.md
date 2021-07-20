# opensource-hardening

A collection of open source hardening tools

## Collections

3rd-party guides

* [unassassinable/PAW - Privileged Access Workstation](https://github.com/unassassinable/PAW)
* [PaulSec/awesome-windows-domain-hardening - A curated list of awesome Security Hardening techniques for Windows](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [ernw/hardening - Repository of Hardening Guides](https://github.com/ernw/hardening)
* [trimstray/the-practical-linux-hardening-guide - This guide details the planning and the tools involved in creating a secure Linux production systems - WIP](https://github.com/trimstray/the-practical-linux-hardening-guide)
* [decalage2/awesome-security-hardening - A collection of awesome security hardening guides, tools and other resources](https://github.com/decalage2/awesome-security-hardening)
* [trimstray/linux-hardening-checklist - Simple checklist to help you deploying the most important areas of the GNU/Linux production systems - WIP](https://github.com/trimstray/linux-hardening-checklist)
* [Group Policy Administrative Templates Catalog - 组策略对应的注册表配置，不仅仅是微软的](https://getadmx.com/)
* [fabacab/awesome-cybersecurity-blueteam - A curated collection of awesome resources, tools, and other shiny things for cybersecurity blue teams](https://github.com/fabacab/awesome-cybersecurity-blueteam)
* [Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)

Windows

* [Microsoft/AttackSurfaceAnalyzer - help you analyze your operating system's security configuration for changes during software installation - 对比安装软件前后的系统状态，如COM组件；然后检查这些组件是否有提权等问题](https://github.com/Microsoft/AttackSurfaceAnalyzer)
* [Microsoft/AaronLocker - Robust and practical application whitelisting for Windows](https://github.com/Microsoft/AaronLocker)
* [A-mIn3/WINspect - Powershell-based Windows Security Auditing Toolbox](https://github.com/A-mIn3/WINspect)
* [securitywithoutborders/hardentools - a utility that disables a number of risky Windows features](https://github.com/securitywithoutborders/hardentools)
* [zodiacon/DriverMon - Monitor activity of any driver](https://github.com/zodiacon/DriverMon)
* [EyeOfRa/WinConMon - a demonstration version of how to monitoring Windows console (starting from Windows 8)](https://github.com/EyeOfRa/WinConMon)
* [ubeeri/Invoke-PWAudit - A PowerShell tool which provides an easy way to check for shared passwords between Windows Active Directory accounts](https://github.com/ubeeri/Invoke-PWAudit)
* [gist: reclaimWindows10.ps1 - This Windows 10 Setup Script turns off a bunch of unnecessary Windows 10 telemetery, bloatware, & privacy things](https://gist.github.com/alirobe/7f3b34ad89a159e6daa1)
* [jephthai/OpenPasswordFilter - An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords](https://github.com/jephthai/OpenPasswordFilter)
* [miriamxyra/EventList - the Baseline Event Analyzer](https://github.com/miriamxyra/EventList)
* [gist: mackwage/windows_hardening.cmd - Script to perform some hardening of Windows OS](https://gist.github.com/mackwage/08604751462126599d7e52f233490efe)
* [arekfurt/WinAWL - sample policies and some assorted notes related to some research into various capabilities of Windows Defender Application Control and AppLocker](https://github.com/arekfurt/WinAWL)
* [NVISO-BE/posh-dsc-windows-hardening - Windows OS Hardening with PowerShell DSC](https://github.com/NVISO-BE/posh-dsc-windows-hardening)
* [glinares/CSCGuard - Protects and logs suspicious and malicious usage of .NET CSC.exe and Runtime C# Compilation - 把csc.exe改名，然后用这个exe替换掉，这样就能拿到csc参数并阻断，没卵用](https://github.com/glinares/CSCGuard)
* [dekuan/VwFirewall - 微盾VirtualWall防火墙整套源代码](https://github.com/dekuan/VwFirewall)
* [AlphaDelta/Secure-Desktop - Anti-keylogger/anti-rat application for Windows - 原理是Desktop隔离，Windows登陆界面也是这个机制](https://github.com/AlphaDelta/Secure-Desktop)
* [ION28/BLUESPAWN - An Active Defense and EDR software to empower Blue Teams - 说是EDR，其实只是一套基线检查，没卵用](https://github.com/ION28/BLUESPAWN)
* [Win8 之后可以调用 SetProcessMitigationPolicy + ProcessSystemCallDisablePolicy 来禁止直接系统调用](https://github.com/chromium/chromium/blob/99314be8152e688bafbbf9a615536bdbb289ea87/base/win/win_util.cc#L595)

Windows AD

* [clr2of8/DPAT - Domain Password Audit Tool for Pentesters](https://github.com/clr2of8/DPAT)
* [canix1/ADACLScanner - Your number one script for ACL's in Active Directory - 找ACL配置缺陷](https://github.com/canix1/ADACLScanner)
* [NotSoSecure/AD_delegation_hunting - An attempt to automated hunting for delegation access across the domain](https://github.com/NotSoSecure/AD_delegation_hunting)
* [cyberark/ACLight - A script for advanced discovery of Privileged Accounts - includes Shadow Admins](https://github.com/cyberark/ACLight)
* [ANSSI-FR/AD-permissions - Active Directory permissions (ACL/ACE) auditing tools](https://github.com/ANSSI-FR/AD-permissions)
* Group policy
  * [gpoguy/GetVulnerableGPO - PowerShell script to find 'vulnerable' security-related GPOs that should be hardended](https://github.com/gpoguy/GetVulnerableGPO)

Linux

* [wazuh - Host and endpoint security](https://github.com/wazuh/wazuh)
* [openwall/lkrg - Linux Kernel Runtime Guard](https://github.com/openwall/lkrg)
  * [OSTconf2020: LKRG In A Nutshell](https://www.openwall.com/presentations/OSTconf2020-LKRG-In-A-Nutshell/OSTconf2020-LKRG-In-A-Nutshell.pdf)
* [trimstray/otseca - Open source security auditing tool to search and dump system configuration. It allows you to generate reports in HTML or RAW-HTML formats](https://github.com/trimstray/otseca)
* [a13xp0p0v/kconfig-hardened-check - A script for checking the hardening options in the Linux kernel config](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [CISOfy/lynis - Lynis - Security auditing tool for Linux, macOS, and UNIX-based systems](https://github.com/CISOfy/lynis)
* [dev-sec/ansible-os-hardening - This Ansible role provides numerous security-related configurations, providing all-round base protection](https://github.com/dev-sec/ansible-os-hardening)
* [uber/pam-ussh - uber's ssh certificate pam module](https://github.com/uber/pam-ussh)
* [yandex/gixy - Nginx configuration static analyzer](https://github.com/yandex/gixy)
* [herecura.au: Kconfig hardening tests - 实际生产环境不可能用的](https://blog.herecura.eu/blog/2020-05-30-kconfig-hardening-tests/)
* [anti-ddos/Anti-DDOS - Takes the necessary defense configurations - 自动设置sysctl配置](https://github.com/anti-ddos/Anti-DDOS)
* [konstruktoid/hardening - Hardening Ubuntu. Systemd edition](https://github.com/konstruktoid/hardening)

MacOS

* [drduh/macOS-Security-and-Privacy-Guide - Guide to securing and improving privacy on macOS](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
* [SAP/macOS-enterprise-privileges - For Mac users in an Enterprise environment this app ensures secure environment and yet gives the User control over administration of their machine by elevating their level of access to Administrator privilege on macOS X - 管理员权限切换工具，很有用](https://github.com/SAP/macOS-enterprise-privileges)

Web app

* [jvoisin/snuffleupagus - Security module for php7 and php8 - Killing bugclasses and virtual-patching the rest](https://github.com/jvoisin/snuffleupagus)

SQLServer

* [sqlcollaborative/dbachecks - a framework created by and for SQL Server pros who need to validate their environments](https://github.com/sqlcollaborative/dbachecks)

Firefox

* [pyllyukko/user.js - Firefox configuration hardening](https://github.com/pyllyukko/user.js)

Sandbox

* [sandboxie - The Sandboxie application 开源了](https://github.com/sandboxie/sandboxie)
* [microsoft/Windows-Sandbox-Utilities - A public repository for useful Windows Sandbox scripts and configurations](https://github.com/microsoft/Windows-Sandbox-Utilities)
* [karkason/pywinsandbox - Windows Sandbox Utillities Python Package - Windows 自带的沙箱](https://github.com/karkason/pywinsandbox)
* [kkamagui/shadow-box-for-x86 - Lightweight and Practical Kernel Protector for x86](https://github.com/kkamagui/shadow-box-for-x86)
* [adtac/fssb - A filesystem sandbox for Linux using syscall intercepts](https://github.com/adtac/fssb)
* [google/gvisor - Container Runtime Sandbox](https://github.com/google/gvisor)
* [google/nsjail - A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters](https://github.com/google/nsjail)
   * [Tutorial: Sandboxing ImageMagick with nsjail](https://offbyinfinity.com/2017/12/sandboxing-imagemagick-with-nsjail/)
* [netblue30/firejail - Linux namespaces and seccomp-bpf sandbox](https://github.com/netblue30/firejail)
* [genuinetools/binctr - Create fully static, including rootfs embedded, binaries that pop you directly into a container](https://github.com/genuinetools/binctr)
* [int0/ProcessIsolator - Utility to hook SSDT of specific process and transfer control to a service (usermode app) for handling to determine action allow/deny API call etc](https://github.com/int0/ProcessIsolator)
* [CheckPointSW/InviZzzible - a tool for assessment of your virtual environments in an easy and reliable way. It contains the most recent and up to date detection and evasion techniques as well as fixes for them](https://github.com/CheckPointSW/InviZzzible)
* Guides
  * [Sandbox Best Practices Cheat Sheet](http://unprotect.tdgt.org/images/2/23/Sandbox-Cheatsheet-1.1.pdf)

Deception

* [bhdresh/Dejavu - DejaVU - Open Source Deception Framework](https://github.com/bhdresh/Dejavu)
* [samratashok/Deploy-Deception - A PowerShell module to deploy active directory decoy objects](https://github.com/samratashok/Deploy-Deception)
  * [Forging Trusts for Deception in Active Directory](http://files.brucon.org/2018/11-Nikhil-Mittal-Forging-Trusts.pdf)

Uncategorized

* [gist: a list of DNS over HTTP service providers](https://gist.github.com/dtmsecurity/a849e985e6a0b61aeb54890ebcfa55eb)
* [CboeSecurity/password_pwncheck - Kerberos / Windows AD / Linux PAM password change check against breached lists (HIBP), and other rules - 多个操作系统的密码模块，防止使用已经暴露的密码](https://github.com/CboeSecurity/password_pwncheck)

## Tutorials

* [asd.gov.au: Hardening Microsoft Windows 10 version 1709 Workstations](https://www.asd.gov.au/publications/protect/Hardening_Win10.pdf)
* [ewnw: Active Directory Security Best Practices](https://www.ernw.de/download/ERNW_ISH_Conference_2019_AD_Security_BP.pdf)
* [slideshare: Active Directory Security Testing Guide - v2.0](https://www.slideshare.net/HuyKha2/adstg-v20-guidance)
* [Mitigate Credential theft with Administrative Tier Model - 好复杂，大公司应该用不起来](https://getshitsecured.com/2020/03/23/mitigate-credential-theft-with-administrative-tier-model/)

