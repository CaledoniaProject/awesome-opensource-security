## Password recovery

From files / registry / database

* [sadshade/veeam-creds - Collection of scripts to retrieve stored passwords from Veeam Backup](https://github.com/sadshade/veeam-creds)
* [MWR-CyberSec/PXEThief - a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager](https://github.com/MWR-CyberSec/PXEThief)
* [gourk/FirePwd.Net - Password reader for Mozilla Firefox and Thunderbird](https://github.com/gourk/FirePwd.Net)
* [wafinfo/Sunflower_get_Password - 向日葵config.ini账号和密码解密工具](https://github.com/wafinfo/Sunflower_get_Password)
* [jeroennijhof/vncpwd - VNC Password Decrypter - 可以处理~/.vnc/passwd的密码](https://github.com/jeroennijhof/vncpwd)
* [tweksteen/jenkins-decrypt - Credentials dumper for Jenkins - python3实现的credentials/config解密工具，还需要改造下](https://github.com/tweksteen/jenkins-decrypt)
* [trinitronx/vncpasswd.py - A Python implementation of vncpasswd, w/decryption abilities & extra features - 可以处理最新版本的 .vnc 文件里的十六进制密码](https://github.com/trinitronx/vncpasswd.py)
* [TideSec/Decrypt_Weblogic_Password - 搜集了市面上绝大部分weblogic解密方式，整理了7种解密weblogic的方法及响应工具](https://github.com/TideSec/Decrypt_Weblogic_Password)
* [Neohapsis/creddump7 - 离线SAM解析工具](https://github.com/Neohapsis/creddump7)
* [stackoverflow: Is there a way to crack the password on an Excel VBA Project - Excel 2007-2016 VBA 密码不是真的保护，只是一个标志位](https://stackoverflow.com/questions/1026483/is-there-a-way-to-crack-the-password-on-an-excel-vba-project)
* [beurtschipper/Depix - Recovers passwords from pixelized screenshots - 1.4K star](https://github.com/beurtschipper/Depix)
* [Hzllaga/RDODecrypt - Remote Desktop Organizer 密码破解](https://github.com/Hzllaga/RDODecrypt)
* [adezz/360se_Browser_getpass - 360SE浏览器密码提取](https://github.com/adezz/360se_Browser_getpass)

From memory

* [liamg/dismember - Scan memory for secrets and more. Maybe eventually a full /proc toolkit](https://github.com/liamg/dismember)
* [djhohnstein/1PasswordSuite - Utilities to extract secrets from 1Password - 注入并执行1Password.dll导出的函数实现解密](https://github.com/djhohnstein/1PasswordSuite)
* [giMini/mimiDbg - PowerShell oneliner to retrieve wdigest passwords from the memory](https://github.com/giMini/mimiDbg)
* [giMini/PowerMemory - Exploit the credentials present in files and memory](https://github.com/giMini/PowerMemory)
* [blendin/3snake - Tool for extracting information from newly spawned processes](https://github.com/blendin/3snake)
* [hc0d3r/mysql-magic - dump mysql client password from memory](https://github.com/hc0d3r/mysql-magic)
* [HarmJ0y/KeeThief - Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory](https://github.com/HarmJ0y/KeeThief)
* [Slowerzs/ThievingFox - a collection of post-exploitation tools to gather credentials from various password managers and windows utilities. Each module leverages a specific method of injecting into the target process, and then hooks internals functions to gather crendentials](https://github.com/Slowerzs/ThievingFox)

From pcap

* [A 9-step recipe to crack a NTLMv2 Hash from a freshly acquired .pcap - 使用wireshark查看NTLMv2流量，手动拼凑hashcat格式的文件](https://research.801labs.org/cracking-an-ntlmv2-hash/)

Stealing

* [oxfemale/LogonCredentialsSteal - LOCAL AND REMOTE HOOK msv1_0!SpAcceptCredentials from LSASS.exe and DUMP DOMAIN/LOGIN/PASSWORD IN CLEARTEXT to text file](https://github.com/oxfemale/LogonCredentialsSteal)
* [nettitude/ETWHash - C# POC to extract NetNTLMv1/v2 hashes from ETW provider](https://github.com/nettitude/ETWHash)
* [jephthai/OpenPasswordFilter - An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords](https://github.com/jephthai/OpenPasswordFilter)
* [gtworek/PSBits/PasswordStealing/NPPSpy - NetworkProvider例子，可以获取登录密码、修改密码事件，能抓取明文；这个里面有注册表配置脚本；这个不用重启，退出登录就可以实现加载](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)
* [gtworek/PSBits/PasswordStealing - NPLogonNotify 方式获取密码，需要重新登录，无需重启](https://github.com/gtworek/PSBits/tree/master/PasswordStealing)
* [0x09AL/RdpThief - Extracting Clear Text Passwords from mstsc.exe using API Hooking - 2019停更](https://github.com/0x09AL/RdpThief)
* [last-byte/HppDLL - local password dumping using MsvpPasswordValidate hooks](https://github.com/last-byte/HppDLL)
* [clymb3r/Misc-Windows-Hacking/HookPasswordChange - 可配合 Invoke-ReflectivePEInjection 注入到 lsass 实现密码修改窃取；这个库无法获取域的名字，而且密码写到了域控主机，不太方便](https://github.com/clymb3r/Misc-Windows-Hacking/tree/master/HookPasswordChange)
  * [CaledoniaProject/PasswordFilter - 非注入版本的，这个有很多其他的实现，比如支持日志加密等等](https://github.com/CaledoniaProject/PasswordFilter)

Suite

* [l0phtcrack/l0phtcrack - L0phtCrack Password Auditor - 商业软件开源了](https://gitlab.com/l0phtcrack/l0phtcrack)
* [AlessandroZ/LaZagne - Credentials recovery project](https://github.com/AlessandroZ/LaZagne)
* [kerbyj/goLazagne - Go library for credentials recovery - 2020停更](https://github.com/kerbyj/goLazagne)
* [twelvesec/passcat - Passwords Recovery Tool (C++)](https://github.com/twelvesec/passcat)
* [Arvanaghi/SessionGopher - a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop](https://github.com/Arvanaghi/SessionGopher)
* [AlessandroZ/LaZagneForensic - Windows passwords decryption from dump files](https://github.com/AlessandroZ/LaZagneForensic)

Uncategorized

* [YuriMB/WinSCP-Password-Recovery - Decrypt stored WinSCP Passwords](https://github.com/YuriMB/WinSCP-Password-Recovery)
* [mubix/solarflare - SolarWinds Orion Account Audit / Password Dumping Utility](https://github.com/mubix/solarflare)
* [securesean/DecryptAutoLogon - Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon - 有LsaRetrievePrivateData C#调用例子](https://github.com/securesean/DecryptAutoLogon)
* [guardicore/azure_password_harvesting - Plaintext Password harvesting from Azure Windows VMs](https://github.com/guardicore/azure_password_harvesting)
* [Ciphey - Automated decryption tool](https://github.com/Ciphey/Ciphey)
* [peewpw/Invoke-WCMDump - PowerShell Script to Dump Windows Credentials from the Credential Manager](https://github.com/peewpw/Invoke-WCMDump)
* [gist: Get-WlanEnterprisePassword.ps1](https://gist.github.com/CaledoniaProject/17973148fb1e49fbcb818f0b7e6e28a7)
* [sekirkity/BrowserGather - Fileless web browser information extraction](https://github.com/sekirkity/BrowserGather)
* [ropnop/windows_sshagent_extract - PoC code to extract private keys from Windows 10's built in ssh-agent service](https://github.com/ropnop/windows_sshagent_extract)
* [HanseSecure/credgrap_ie_edge - Extract stored credentials from Internet Explorer and Edge](https://github.com/HanseSecure/credgrap_ie_edge)


