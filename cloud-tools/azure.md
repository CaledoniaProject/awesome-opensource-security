## Azure

Account security

* [quahac/Azure-AD-Password-Checker - In an Azure AD environment, it's possible to determine whether a user has Multi-Factor Authentication (MFA) disabled without requiring any special privileges](https://github.com/quahac/Azure-AD-Password-Checker)

Uncategorized

* [Azure/Stormspotter - Azure Red Team tool for graphing Azure and Azure Active Directory objects](https://github.com/Azure/Stormspotter)
* [Azure security best practices and patterns - 有个PDF电子书](https://docs.microsoft.com/en-us/azure/security/security-best-practices-and-patterns)
* [hausec/PowerZure - PowerShell framework to assess Azure security](https://github.com/hausec/PowerZure)
* [fireeye/ADFSpoof - A python tool to forge AD FS security tokens](https://github.com/fireeye/ADFSpoof)
* [nccgroup/azucar - Security auditing tool for Azure environments](https://github.com/nccgroup/azucar/)
* [fox-it/adconnectdump - Dump Azure AD Connect credentials for Azure AD and Active Directory](https://github.com/fox-it/adconnectdump)
* [NetSPI/MicroBurst - A collection of scripts for assessing Microsoft Azure security](https://github.com/NetSPI/MicroBurst)
* [christophetd/Adaz - Automatically deploy customizable Active Directory labs in Azure](https://github.com/christophetd/Adaz)
* [LaresLLC/AzureTokenExtractor - Extracts Azure authentication tokens from PowerShell process minidumps - 从内存里定位认证信息，然后用Import-AzContext导入认证信息](https://github.com/LaresLLC/AzureTokenExtractor)

Resources

* [Cloud-Architekt/AzureAD-Attack-Defense - This publication is a collection of various common attack scenarios on Azure Active Directory and how they can be mitigated or detected](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
* [rootsecdev/Azure-Red-Team - Azure Security Resources and Notes](https://github.com/rootsecdev/Azure-Red-Team)
* [netspi: Azure Privilege Escalation via Cloud Shell - Cloud Shell 是一个 Linux 镜像，可以通过替换 storage 里的文件，实现后门功能，比如记录创建VM用的密码等等。官方认为授予storage权限不算漏洞，所以不会修复](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [adsecurity: From Azure AD to Active Directory (via Azure) – An Unanticipated Attack Path - GA可以给自己管理AD对应的subscription的权限，之后可以修改所有资源，比如在VM里执行ps脚本](https://adsecurity.org/?p=4277)
* [xpnsec: Azure AD Connect for Red Teamers - 在 Pass-through Authentication 模式下，密码在本地认证，可以通过挂钩LogonUser直接获取明文密码；ADSync 配置存在本地SQLSERVER，文章里有解密脚本](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Azure Active Directory Pass-Through Authentication Flaws - 分析PT Agent协议，实现自己的agent来监听认证事件并盗取密码](https://www.secureworks.com/research/azure-active-directory-pass-through-authentication-flaws)
