# MacOS library

Uncategorized

* [seemoo-lab/dtrace-memaccess_cve-2020-27949 - Reading and writing memory of other processes using fasttrap - 有个fasttrap例子](https://github.com/seemoo-lab/dtrace-memaccess_cve-2020-27949)
* [Audio Unit Plug-ins Legitimate Un-signed Code Execution](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
* [briankendall/proxy-audio-device - A virtual audio driver for macOS to sends all audio to another output](https://github.com/briankendall/proxy-audio-device)
* [rodionovd/rd_route - Function hooking for macOS](https://github.com/rodionovd/rd_route)
* [DeVaukz/MachO-Kit - A C/Objective-C library for parsing Mach-O files](https://github.com/DeVaukz/MachO-Kit)
* [its-a-feature/bifrost - Objective-C library and console to interact with Heimdal APIs for macOS Kerberos](https://github.com/its-a-feature/bifrost)
* [gist: Ask for privilege to execute command](https://gist.github.com/TomLiu/5811875)
  * [objective-see: Sniffing Authentication References on macOS - details of a privilege-escalation vulnerability (CVE-2017-7170)](https://objective-see.com/blog/blog_0x55.html)
  * [speakerdeck: Job(s) Bless Us! Privileged Operations on macOS - by vashchenko](https://speakerdeck.com/vashchenko/job-s-bless-us-privileged-operations-on-macos?slide=44)
* [MythicAgents/poseidon/Payload_Type/poseidon/agent_code](https://github.com/MythicAgents/poseidon/tree/master/Payload_Type/poseidon/agent_code)

Endpoint security framework

* [gist: An example of using the libEndpointSecurity.dylib in Catalina - Mac下面的各种监控回调，需要特殊的entitlements，没测试](https://gist.github.com/knightsc/4678757164b2c63a58856a1acb3dd17e)
* [willyu-elastic/SimpleEndpoint - Sample code for macOS Extensions](https://github.com/willyu-elastic/SimpleEndpoint)

Network Extension

* [objective-see/DNSMonitor - A DNS Monitor, leveraging Apple's NEDNSProxyProvider/Network Extension Framework](https://github.com/objective-see/DNSMonitor)

Virtualization

* [KhaosT/MacVM - macOS VM for Apple Silicon using Virtualization API](https://github.com/KhaosT/MacVM)
* [NyanSatan/Virtual-iBoot-Fun - Another Virtualization.framework demo project, with focus to iBoot (WIP)](https://github.com/NyanSatan/Virtual-iBoot-Fun)
* [xpnsec: Bring Your Own VM - Mac Edition](https://blog.xpnsec.com/bring-your-own-vm-mac-edition/)

Hook

* [CodeTips/BaiduNetdiskPlugin-macOS - 功能本身已经失效了，但是 method_exchangeImplementations hook 函数的代码可以参考](https://github.com/CodeTips/BaiduNetdiskPlugin-macOS)

XPC

* [securing/SimpleXPCApp - Secure example of an XPC helper written in Swift - 用audit token来认证调用者，比PID安全](https://github.com/securing/SimpleXPCApp)

Kext

* [sektioneins/SUIDGuard - a TrustedBSD Kernel Extension that adds mitigations to protect SUID/SGID processes a bit more](https://github.com/sektioneins/SUIDGuard)
* [kpwn/NULLGuard - kext kills all 32bit binaries lacking PAGEZERO (required for exploitation of kernel NULL derefs)](https://github.com/kpwn/NULLGuard)

Memory Loading

* [xpn/DyldDeNeuralyzer - A simple set of POCs to demonstrate in-memory loading of Mach-O's](https://github.com/xpn/DyldDeNeuralyzer)
* [CylanceVulnResearch/osx_runbin - Running Executables on macOS from Memory](https://github.com/CylanceVulnResearch/osx_runbin)
* [slyd0g.medium.com: Understanding and Defending Against Reflective Code Loading on macOS](https://slyd0g.medium.com/understanding-and-defending-against-reflective-code-loading-on-macos-e2e83211e48f)
  * [slyd0g/SwiftInMemoryLoading - Swift implementation of in-memory Mach-O loading on macOS](https://github.com/slyd0g/SwiftInMemoryLoading)
  * [djhohnstein/macos_shell_memory - Execute MachO binaries in memory using CGo](https://github.com/djhohnstein/macos_shell_memory)
