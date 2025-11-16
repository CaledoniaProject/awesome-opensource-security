DDoS

* [Kleptocratic/DNS-Fender - A Proof-of-Concept tool utilizing open DNS resolvers to produce an amplification attack against web servers. Using Shodan APIs and native Linux commands, this tool is in development to cripple web servers using spoofed DNS recursive queries](https://github.com/Kleptocratic/DNS-Fender)
* [649/Memcrashed-DDoS-Exploit - DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API](https://github.com/649/Memcrashed-DDoS-Exploit/)
* [OffensivePython/Saddam - DDoS Amplification Tool](https://github.com/OffensivePython/Saddam)
* [valyala/goloris - Slowloris for nginx DoS. Written in go](https://github.com/valyala/goloris)
* [jseidl/GoldenEye - GoldenEye Layer 7 (KeepAlive+NoCache) DoS Test Tool](https://github.com/jseidl/GoldenEye)
* [anti-ddos/Anti-DDOS - Takes the necessary defense configurations - 自动设置sysctl配置](https://github.com/anti-ddos/Anti-DDOS)
* [2018.7 How to drop 10 million packets per second](https://blog.cloudflare.com/how-to-drop-10-million-packets/)
* [BCP38 is RFC2827: Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing](http://www.bcp38.info/index.php/Main_Page)

Firewall

* [trustedsec/egressbuster - a method to check egress filtering and identify if ports are allowed. If they are, you can automatically spawn a shell](https://github.com/trustedsec/egressbuster)
* [AMOSSYS/Fragscapy - a command-line tool to fuzz network protocols by automating the modification of outgoing network packets. It can run multiple successive tests to determine which options can be used to evade firewalls and IDS](https://github.com/AMOSSYS/Fragscapy)

IPv6

* [dlrobertson/sylkie - IPv6 address spoofing with the Neighbor Discovery Protocol](https://github.com/dlrobertson/sylkie)
* [fgont/ipv6toolkit - SI6 Networks' IPv6 Toolkit](https://github.com/fgont/ipv6toolkit)
* [daikerSec/windows_protocol - 熟悉内网渗透的应该都对IPC，黄金票据，白银票据，NTLM Relay，Pth,Ptt,Ptk，PTC 这些词汇再熟悉不够了，对其利用工具也了如指掌，但是有些人对里面使用的原理还不太了解，知其然不知其所以然，本系列文章就针对内网渗透的常见协议(如kerberos,ntlm,smb,ldap,netbios等)进行分析，介绍相关漏洞分析以及漏洞工具分析利用](https://github.com/daikerSec/windows_protocol)
* [360-A-Team/NtlmSocks - a pass-the-hash tool - 开启一个socks代理，在流量中匹配NTLMSSP数据包，替换其中错误的NT哈希和会话密钥](https://github.com/360-A-Team/NtlmSocks)
* [yadutaf/tracepkt - Trace a ping packet journey across network interfaces and namespace on recent Linux](https://github.com/yadutaf/tracepkt)

TCP

* [kpcyrd/rshijack - TCP connection hijacker, Rust rewrite of shijack](https://github.com/kpcyrd/rshijack)

QUIC

* [SMB over QUIC](https://blog.xpnsec.com/ntlmquic)

FTP

* [dfyz/ctf-writeups/hxp-2020/resonator - 编写假的FTP服务器，强制客户端使用被动模式，并向特定地址发起SSRF。需要服务器地址和上传内容同时可控才能利用。](https://github.com/dfyz/ctf-writeups/tree/master/hxp-2020/resonator)

RTSP

* [Ullaakut/cameradar - Cameradar hacks its way into RTSP videosurveillance cameras](https://github.com/Ullaakut/cameradar)
* [googleprojectzero/Street-Party - a suite of tools that allows the RTP streams of video conferencing implementations to be viewed and modified](https://github.com/googleprojectzero/Street-Party)
* [Ullaakut/camerattack - An attack tool designed to remotely disable CCTV camera streams (like in spy movies)](https://github.com/Ullaakut/camerattack)

SDN

* [smythtech/sdnpwn - An SDN penetration testing toolkit](https://github.com/smythtech/sdnpwn)
* [OpenNetworkingFoundation/DELTA - SDN SECURITY EVALUATION FRAMEWORK](https://github.com/OpenNetworkingFoundation/DELTA)

SSDP

* [initstring/evil-ssdp - Spoof SSDP replies to phish for credentials and NetNTLM challenge/response. Creates a fake UPNP device, tricking users into visiting a malicious phishing page. Also detects and exploits XXE 0-day vulnerabilities in XML parsers for UPNP-enabled apps](https://gitlab.com/initstring/evil-ssdp)

UPnP

* [dc414/Upnp-Exploiter - A Upnp exploitation tool - 开UPnP代理的](https://github.com/dc414/Upnp-Exploiter)

DHCP

* [mschwager/dhcpwn - a tool used for testing DHCP IP exhaustion attacks. It can also be used to sniff local DHCP traffic](https://github.com/mschwager/dhcpwn)

NAC

* [Ethernet ghosting & NAC bypass – A practical overview](https://www.immunit.ch/blog/2022/10/26/ethernet-ghosting-nac-bypass/)

VLAN

* [commonexploits/vlan-hopping - Easy 802.1Q VLAN Hopping](https://github.com/commonexploits/vlan-hopping)
* [tomac/yersinia - A framework for layer 2 attacks](https://github.com/tomac/yersinia)

Radius

* [ANSSI-FR/audit-radius - A RADIUS authentication server audit tool](https://github.com/ANSSI-FR/audit-radius)

RDP

* [klinix5/ReverseRDP_RCE - 使用CreateMountPoint来获取tsclient路径，可能有点用 - CVE-2022-21990，仓库已经被删除](https://web.archive.org/web/20220427034157/https://github.com/klinix5/ReverseRDP_RCE)
* [nccgroup/SocksOverRDP - Socks5/4/4a Proxy support for Remote Desktop Protocol / Terminal Services / Citrix / XenApp / XenDesktop](https://github.com/nccgroup/SocksOverRDP)
* [NotMedic/rdp-tunnel - Pre-compiled tools to tunnel TCP over RDP Connections](https://github.com/NotMedic/rdp-tunnel)
* [linuz/Sticky-Keys-Slayer - Scans for accessibility tools backdoors via RDP](https://github.com/linuz/Sticky-Keys-Slayer)
* [stascorp/rdpwrap - enable Remote Desktop Host support and concurrent RDP sessions on reduced functionality systems for home usage - RDP多开，2018停更](https://github.com/stascorp/rdpwrap)
* [aurel26/TS-Security-Editor - Terminal Service (RDP) Security Editor](https://github.com/aurel26/TS-Security-Editor)
* [渗透技巧 - 使用远程桌面协议建立通道 - 后期用处不大](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E4%BD%BF%E7%94%A8%E8%BF%9C%E7%A8%8B%E6%A1%8C%E9%9D%A2%E5%8D%8F%E8%AE%AE%E5%BB%BA%E7%AB%8B%E9%80%9A%E9%81%93/)
* [earthquake/UniversalDVC - Universal Dynamic Virtual Channel connector for Remote Desktop Services](https://github.com/earthquake/UniversalDVC)
* [V-E-O/rdp2tcp - open tcp tunnel through remote desktop connection](https://github.com/V-E-O/rdp2tcp)

SSH
 
* [ncsa/ssh-auditor - The best way to scan for weak ssh passwords on your network - 支持重新检查密码是否还能用，以及不同主机的hostkey是否相同](https://github.com/ncsa/ssh-auditor)
* [salesforce/hassh - a network fingerprinting standard which can be used to identify specific Client and Server SSH implementations](https://github.com/salesforce/hassh)

SSL

* [neykov/extract-tls-secrets - Decrypt HTTPS/TLS connections on the fly with Wireshark - 支持TLSv1.3](https://github.com/neykov/extract-tls-secrets/)
* [salesforce/ja3 - a standard for creating SSL client fingerprints in an easy to produce and shareable way](https://github.com/salesforce/ja3)
* [salesforce/jarm - an active Transport Layer Security (TLS) server fingerprinting tool](https://github.com/salesforce/jarm)
* [cedowens/C2-JARM - A list of JARM hashes for different ssl implementations used by some C2/red team tools](https://github.com/cedowens/C2-JARM)
* [CUCyber/ja3transport - Impersonating JA3 signatures](https://github.com/CUCyber/ja3transport)
* [FoxIO-LLC/ja4 - JA4+ is a suite of network fingerprinting standards](https://github.com/FoxIO-LLC/ja4)
* [drwetter/testssl.sh - Testing TLS/SSL encryption anywhere on any port](https://github.com/drwetter/testssl.sh)
* [sumanj/frankencert - Adversarial Testing of Certificate Validation in SSL/TLS Implementations](https://github.com/sumanj/frankencert)
* [hahwul/a2sv - Auto Scanning to SSL Vulnerability](https://github.com/hahwul/a2sv)
* [SixGenInc/Noctilucent - Using TLS 1.3 to evade censors, bypass network defenses, and blend in with the noise](https://github.com/SixGenInc/Noctilucent)
* [adulau/ssldump - composed of the original SSLDUMP 0.9b3 + a myriad of patches (from Debian and other distributions) + contributions via PR](https://github.com/adulau/ssldump)

VoIP

* [meliht/Mr.SIP - SIP-Based Audit and Attack Tool](https://github.com/meliht/Mr.SIP)
* [EnableSecurity/sipvicious - a set of security tools that can be used to audit SIP based VoIP systems](https://github.com/EnableSecurity/sipvicious)
* [Viproy VoIP Penetration Testing and Exploitation Kit](http://viproy.com/)
* [jesusprubio/bluebox-ng - Pentesting framework using Node.js powers, focused in VoIP](https://github.com/jesusprubio/bluebox-ng)
* [eurialo/vsaudit - VOIP Security Audit Framework](https://github.com/eurialo/vsaudit)
* [SySS-Research/WireBug - a toolset for Voice-over-IP penetration testing](https://github.com/SySS-Research/WireBug)

MQTT

* [akamai-threat-research/mqtt-pwn - MQTT-PWN intends to be a one-stop-shop for IoT Broker penetration-testing and security assessment operations](https://github.com/akamai-threat-research/mqtt-pwn)
* [thomasnordquist/MQTT-Explorer - a comprehensive and easy-to-use MQTT Client - 1.4K star，图形界面](https://github.com/thomasnordquist/MQTT-Explorer)

Redis

* [Ridter/redis-rce - Redis 4.x/5.x RCE - 利用同步机制写module并加载](https://github.com/Ridter/redis-rce)
* [iSafeBlue/redis-rce - Redis RCE 的几种方法](https://github.com/iSafeBlue/redis-rce)
* [n0b0dyCN/redis-rogue-server - Redis(<=5.0.5) RCE，不支持windows，没做错误处理](https://github.com/n0b0dyCN/redis-rogue-server)
* [r35tart/RedisWriteFile - 通过 Redis 主从写出无损文件](https://github.com/r35tart/RedisWriteFile)

Wireshark

* [CoreSecurity/SAP-Dissection-plug-in-for-Wireshark - This Wireshark plugin provides dissection on SAP's NI, Message Server, Router, Diag and Enqueue protocols](https://github.com/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark)
* [pentesteracademy/patoolkit - PA Toolkit is a collection of traffic analysis plugins focused on security - LUA 插件](https://github.com/pentesteracademy/patoolkit)
* [JohnDMcMaster/usbrply - Replay USB messages from Wireshark (.cap) files](https://github.com/JohnDMcMaster/usbrply)
* [airbus-cert/Winshark - A wireshark plugin to instrument ETW](https://github.com/airbus-cert/Winshark)
* [Wireshark for Pentester: Decrypting RDP Traffic](https://www.hackingarticles.in/wireshark-for-pentester-decrypting-rdp-traffic/)

Nmap

* [cldrn/nmap-nse-scripts - My collection of nmap NSE scripts](https://github.com/cldrn/nmap-nse-scripts)
* [vulnersCom/nmap-vulners - NSE script based on Vulners.com API](https://github.com/vulnersCom/nmap-vulners)
* [scipag/vulscan - Advanced vulnerability scanning with Nmap NSE](https://github.com/scipag/vulscan)
* [whickey-r7/grab_beacon_config - NSE脚本，获取CS配置](https://github.com/whickey-r7/grab_beacon_config)
* [milo2012/ipv4Bypass - Using IPv6 to Bypass Security - 使用mac等信息，从IPv4地址推算IPv6地址，进而转换为扫描IPv6地址，绕过防火墙](https://github.com/milo2012/ipv4Bypass)
* [al0ne/Nmap_Bypass_IDS - Nmap&Zmap特征识别，绕过IDS探测](https://github.com/al0ne/Nmap_Bypass_IDS)
* [trimstray/sandmap - a tool supporting network and system reconnaissance using the massive Nmap engine. It provides a user-friendly interface, automates and speeds up scanning and allows you to easily use many advanced scanning techniques](https://github.com/trimstray/sandmap)
* [x90skysn3k/brutespray - Brute-Forcing from Nmap output - Automatically attempts default creds on found services](https://github.com/x90skysn3k/brutespray)

Nessus

* [DanMcInerney/msf-autoshell - Feed the tool a .nessus file and it will automatically get you MSF shell](https://github.com/DanMcInerney/msf-autoshell)
* [sdcampbell/Nessusploitable - Parses Nessus .nessus files for exploitable vulnerabilities and outputs a report file in format MM-DD-YYYY-nessus.csv](https://github.com/sdcampbell/Nessusploitable)

Responder

* [joda32/got-responded - A simple tool to detect NBT-NS and LLMNR spoofing (and messing with them a bit)](https://github.com/joda32/got-responded)

OpenVAS

* [greenbone/openvas - OpenVAS remote network security scanner](https://github.com/greenbone/openvas)
