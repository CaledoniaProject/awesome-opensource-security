## 3rd-party lists

* [toniblyx/my-arsenal-of-aws-security-tools - List of open source tools for AWS security: defensive, offensive, auditing, DFIR, etc](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
* [gist: AWS Security Resources](https://gist.github.com/chanj/6c48c059ad4b72a60bf3)
* [dafthack/CloudPentestCheatsheets - a collection of cheatsheets I have put together for tools related to pentesting organizations that leverage cloud providers - 一共就没几个链接，醉了](https://github.com/dafthack/CloudPentestCheatsheets)

## Uncategorized

* [initstring/cloud_enum - Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud](https://github.com/initstring/cloud_enum)
* [google/cloud-forensics-utils - some tools to be used by forensics teams to collect evidence from cloud platforms - python libcloudforensics 库代码](https://github.com/google/cloud-forensics-utils)

## DigitalOcean

* [appsecco/spaces-finder - A tool to hunt for publicly accessible DigitalOcean Spaces](https://github.com/appsecco/spaces-finder)

## Aliyun

* [aliyun/oss-browser - OSS Browser 提供类似windows资源管理器功能。用户可以很方便的浏览文件，上传下载文件，支持断点续传等](https://github.com/aliyun/oss-browser)

## Azure

Uncategorized

* [hausec/PowerZure - PowerShell framework to assess Azure security](https://github.com/hausec/PowerZure)
* [fireeye/ADFSpoof - A python tool to forge AD FS security tokens](https://github.com/fireeye/ADFSpoof)
* [dirkjanm/ROADtools - The Azure AD exploration framework](https://github.com/dirkjanm/ROADtools)
* [nccgroup/azucar - Security auditing tool for Azure environments](https://github.com/nccgroup/azucar/)
* [fox-it/adconnectdump - Dump Azure AD Connect credentials for Azure AD and Active Directory](https://github.com/fox-it/adconnectdump)
* [NetSPI/MicroBurst - A collection of scripts for assessing Microsoft Azure security](https://github.com/NetSPI/MicroBurst)
* [christophetd/Adaz - Automatically deploy customizable Active Directory labs in Azure](https://github.com/christophetd/Adaz)
* [LaresLLC/AzureTokenExtractor - Extracts Azure authentication tokens from PowerShell process minidumps - 从内存里定位认证信息，然后用Import-AzContext导入认证信息](https://github.com/LaresLLC/AzureTokenExtractor)

Resources

* [netspi: Azure Privilege Escalation via Cloud Shell - Cloud Shell 是一个 Linux 镜像，可以通过替换 storage 里的文件，实现后门功能，比如记录创建VM用的密码等等。官方认为授予storage权限不算漏洞，所以不会修复](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [adsecurity: From Azure AD to Active Directory (via Azure) – An Unanticipated Attack Path - GA可以给自己管理AD对应的subscription的权限，之后可以修改所有资源，比如在VM里执行ps脚本](https://adsecurity.org/?p=4277)
* [xpnsec: Azure AD Connect for Red Teamers - 在 Pass-through Authentication 模式下，密码在本地认证，可以通过挂钩LogonUser直接获取明文密码；ADSync 配置存在本地SQLSERVER，文章里有解密脚本](https://blog.xpnsec.com/azuread-connect-for-redteam/)

### GCP

* [RhinoSecurityLabs/GCPBucketBrute - A script to enumerate Google Storage buckets, determine what access you have to them, and determine if they can be privilege escalated](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
