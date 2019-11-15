# opensource-hardening

A collection of open source hardening tools

## Collections

3rd-party guides

* [unassassinable/PAW - Privileged Access Workstation](https://github.com/unassassinable/PAW)
* [PaulSec/awesome-windows-domain-hardening - A curated list of awesome Security Hardening techniques for Windows](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [ernw/hardening - Repository of Hardening Guides](https://github.com/ernw/hardening)
* [trimstray/the-practical-linux-hardening-guide - This guide details the planning and the tools involved in creating a secure Linux production systems - WIP](https://github.com/trimstray/the-practical-linux-hardening-guide)
* [decalage2/awesome-security-hardening - A collection of awesome security hardening guides, tools and other resources](https://github.com/decalage2/awesome-security-hardening)
* [Azure security best practices and patterns - 有个PDF电子书](https://docs.microsoft.com/en-us/azure/security/security-best-practices-and-patterns)
* [trimstray/linux-hardening-checklist - Simple checklist to help you deploying the most important areas of the GNU/Linux production systems - WIP](https://github.com/trimstray/linux-hardening-checklist)

Windows

* [Microsoft/AaronLocker - Robust and practical application whitelisting for Windows](https://github.com/Microsoft/AaronLocker)
* [A-mIn3/WINspect - Powershell-based Windows Security Auditing Toolbox](https://github.com/A-mIn3/WINspect)
* [securitywithoutborders/hardentools - a utility that disables a number of risky Windows features](https://github.com/securitywithoutborders/hardentools)
* [zodiacon/DriverMon - Monitor activity of any driver](https://github.com/zodiacon/DriverMon)
* [EyeOfRa/WinConMon - a demonstration version of how to monitoring Windows console (starting from Windows 8)](https://github.com/EyeOfRa/WinConMon)
* [ubeeri/Invoke-PWAudit - A PowerShell tool which provides an easy way to check for shared passwords between Windows Active Directory accounts](https://github.com/ubeeri/Invoke-PWAudit)
* [gist: reclaimWindows10.ps1 - This Windows 10 Setup Script turns off a bunch of unnecessary Windows 10 telemetery, bloatware, & privacy things](https://gist.github.com/alirobe/7f3b34ad89a159e6daa1)
* [jephthai/OpenPasswordFilter - An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords](https://github.com/jephthai/OpenPasswordFilter)
* [miriamxyra/EventList - the Baseline Event Analyzer](https://github.com/miriamxyra/EventList)
* [Microsoft/AttackSurfaceAnalyzer - help you analyze your operating system's security configuration for changes during software installation](https://github.com/Microsoft/AttackSurfaceAnalyzer)
* [gist: mackwage/windows_hardening.cmd - Script to perform some hardening of Windows OS](https://gist.github.com/mackwage/08604751462126599d7e52f233490efe)
* [arekfurt/WinAWL - sample policies and some assorted notes related to some research into various capabilities of Windows Defender Application Control and AppLocker](https://github.com/arekfurt/WinAWL)

Windows AD

* [clr2of8/DPAT - Domain Password Audit Tool for Pentesters](https://github.com/clr2of8/DPAT)
* [canix1/ADACLScanner - Your number one script for ACL's in Active Directory - 找ACL配置缺陷](https://github.com/canix1/ADACLScanner)
* [NotSoSecure/AD_delegation_hunting - An attempt to automated hunting for delegation access across the domain](https://github.com/NotSoSecure/AD_delegation_hunting)
* [cyberark/ACLight - A script for advanced discovery of Privileged Accounts - includes Shadow Admins](https://github.com/cyberark/ACLight)
* [ANSSI-FR/AD-permissions - Active Directory permissions (ACL/ACE) auditing tools](https://github.com/ANSSI-FR/AD-permissions)
* Group policy
  * [gpoguy/GetVulnerableGPO - PowerShell script to find 'vulnerable' security-related GPOs that should be hardended](https://github.com/gpoguy/GetVulnerableGPO)

Linux

* [openwall: LKRG - Linux Kernel Runtime Guard](http://www.openwall.com/lkrg/)
* [trimstray/otseca - Open source security auditing tool to search and dump system configuration. It allows you to generate reports in HTML or RAW-HTML formats](https://github.com/trimstray/otseca)
* [a13xp0p0v/kconfig-hardened-check - A script for checking the hardening options in the Linux kernel config](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [CISOfy/lynis - Lynis - Security auditing tool for Linux, macOS, and UNIX-based systems](https://github.com/CISOfy/lynis)
* [dev-sec/ansible-os-hardening - This Ansible role provides numerous security-related configurations, providing all-round base protection](https://github.com/dev-sec/ansible-os-hardening)
* [uber/pam-ussh - uber's ssh certificate pam module](https://github.com/uber/pam-ussh)
* [yandex/gixy - Nginx configuration static analyzer](https://github.com/yandex/gixy)

MacOS

* [drduh/macOS-Security-and-Privacy-Guide - Guide to securing and improving privacy on macOS](https://github.com/drduh/macOS-Security-and-Privacy-Guide)

SQLServer

* [sqlcollaborative/dbachecks - a framework created by and for SQL Server pros who need to validate their environments](https://github.com/sqlcollaborative/dbachecks)

Firefox

* [pyllyukko/user.js - Firefox configuration hardening](https://github.com/pyllyukko/user.js)

Sandbox

* [kkamagui/shadow-box-for-x86 - Lightweight and Practical Kernel Protector for x86](https://github.com/kkamagui/shadow-box-for-x86)
* [adtac/fssb - A filesystem sandbox for Linux using syscall intercepts](https://github.com/adtac/fssb)
* [google/gvisor - Container Runtime Sandbox](https://github.com/google/gvisor)
* [google/nsjail - A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters](https://github.com/google/nsjail)
   * [Tutorial: Sandboxing ImageMagick with nsjail](https://offbyinfinity.com/2017/12/sandboxing-imagemagick-with-nsjail/)
* [netblue30/firejail - Linux namespaces and seccomp-bpf sandbox](https://github.com/netblue30/firejail)
* [genuinetools/binctr - Create fully static, including rootfs embedded, binaries that pop you directly into a container](https://github.com/genuinetools/binctr)

Deception

* [bhdresh/Dejavu - DejaVU - Open Source Deception Framework](https://github.com/bhdresh/Dejavu)
* [samratashok/Deploy-Deception - A PowerShell module to deploy active directory decoy objects](https://github.com/samratashok/Deploy-Deception)

Uncategorized

* [gist: a list of DNS over HTTP service providers](https://gist.github.com/dtmsecurity/a849e985e6a0b61aeb54890ebcfa55eb)

## Tutorials

* [asd.gov.au: Hardening Microsoft Windows 10 version 1709 Workstations](https://www.asd.gov.au/publications/protect/Hardening_Win10.pdf)
* [ewnw: Active Directory Security Best Practices](https://www.ernw.de/download/ERNW_ISH_Conference_2019_AD_Security_BP.pdf)
* [slideshare: Active Directory Security Testing Guide - v2.0](https://www.slideshare.net/HuyKha2/adstg-v20-guidance)


