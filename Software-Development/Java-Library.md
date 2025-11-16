Heap Analysis

* [corener/JavaPassDump - 红队实战中，有遇到数据库的配置信息加密的情况，有些甚至在Native层处理加解密，为简化红队流程，产生一个通用的数据库信息提取工具 - 这个是执行OQL查询，没开源但是逻辑很简单](https://github.com/corener/JavaPassDump)
* [wyzxxz/heapdump_tool - heapdump敏感信息查询工具，例如查找 spring heapdump中的密码明文，AK,SK等 - 没开源，看了下代码质量非常差](https://github.com/wyzxxz/heapdump_tool)
* [whwlsfb/JDumpSpider - HeapDump敏感信息提取工具 - 这个是遍历heap搜索](https://github.com/whwlsfb/JDumpSpider)

Decompiler

* [jar-analyzer - JAR包分析工具，批量分析搜索，方法调用关系搜索，字符串搜索，Spring分析，CFG分析，JVM Stack Frame分析等众多功能](https://github.com/jar-analyzer/jar-analyzer)
* [KingBridgeSS/jdifferer - Jdifferer是一个用来比较两个java jar文件的GUI应用，方便开发者和安全研究人员快速找到两个jar文件的不同](https://github.com/KingBridgeSS/jdifferer/)
* [Wker666/wJa - 一个集成了反编译的Java审计工具，有界面](https://github.com/Wker666/wJa)
* [zifeihan/friday - java runtime decompiler (java实时反编译工具)](https://github.com/zifeihan/friday)
* [java-decompiler/jd-gui - A standalone Java Decompiler GUI](https://github.com/java-decompiler/jd-gui)
* [deathmarine/Luyten - An Open Source Java Decompiler Gui for Procyon](https://github.com/deathmarine/Luyten)
* [Storyyeller/Krakatau - Java decompiler, assembler, and disassembler](https://github.com/Storyyeller/Krakatau)
* [MinecraftForge/FernFlower - the first actually working analytical decompiler for Java and probably for a high-level programming language in general](https://github.com/MinecraftForge/FernFlower)
* [konloch/bytecode-viewer - A Java 8 Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More)](https://github.com/konloch/bytecode-viewer)
* [Securityinbits/blog-posts/java_agent - 使用javaagent将每一个加载的class字节码存储下来](https://github.com/Securityinbits/blog-posts/tree/master/java_agent)
* [zxh0/classpy - GUI tool for investigating Java class files](https://github.com/zxh0/classpy)
* [leibnitz27/cfr - This is the public repository for the CFR Java decompiler](https://github.com/leibnitz27/cfr)

War

* [KINGSABRI/godofwar - Malicious Java WAR builder with built-in payloads](https://github.com/KINGSABRI/godofwar)

Debugger

* [CodeMason/JavaSnoop](https://github.com/CodeMason/JavaSnoop)
* [alibaba/jvm-sandbox-repeater - 基于JVM-Sandbox的录制/回放通用解决方案](https://github.com/alibaba/jvm-sandbox-repeater)

Editor

* [GraxCode/JByteMod-Beta - a multifunctional bytecode editor with syntax highlighting and live decompiling and method graphing - 有界面](https://github.com/GraxCode/JByteMod-Beta)
* [Col-E/Recaf - A modern Java bytecode editor](https://github.com/Col-E/Recaf)
* [yzddmr6.tk: 无java环境修改字节码 - 修改CONSTANT_utf8_info常量池结构体，解决java payload参数硬编码的问题，蚁剑As-Exploits就用的这个方案](https://yzddmr6.com/posts/node-edit-java-class/)

JMX

* [qtc-de/beanshooter - JMX enumeration and attacking tool](https://github.com/qtc-de/beanshooter)

JDWP

* [IOActive/jdwp-shellifier - JDWP exploitation script](https://github.com/IOActive/jdwp-shellifier)
* [HowTo: intercept mutually-authenticated TLS communications of a Java thick client - jdb下断点，打印函数参数的例子](https://offsec.almond.consulting/java-tls-intercept.html)

JNDI

* [qi4L/JYso - It can be either a JNDIExploit or a ysoserial](https://github.com/qi4L/JYso)
* [X1r0z/JNDIMap - JNDI 注入利用工具, 支持 RMI 和 LDAP 协议, 包含多种高版本 JDK 绕过方式](https://github.com/X1r0z/JNDIMap)
* [wyzxxz/jndi_tool - JNDI服务利用工具 RMI/LDAP，支持部分场景回显、内存shell，高版本JDK场景下利用等，fastjson rce命令执行，log4j rce命令执行 漏洞检测辅助工具](https://github.com/wyzxxz/jndi_tool)
* [rebeyond/JNDInjector - 一个高度可定制化的JNDI和Java反序列化利用工具](https://github.com/rebeyond/JNDInjector)
* [jas502n/JNDIExploit-1 - 一款用于JNDI注入利用的工具，大量参考/引用了Rogue JNDI项目的代码，支持直接植入内存shell，并集成了常见的bypass 高版本JDK的方式，适用于与自动化工具配合使用 - 内置多个ldap路径](https://github.com/jas502n/JNDIExploit-1)
* [quentinhardy/jndiat - JNDI Attacking Tool](https://github.com/quentinhardy/jndiat)
* [welk1n/JNDI-Injection-Exploit - JNDI注入测试工具](https://github.com/welk1n/JNDI-Injection-Exploit)
* [welk1n/JNDI-Injection-Bypass - Some payloads of JNDI Injection in JDK 1.8.0_191+](https://github.com/welk1n/JNDI-Injection-Bypass)
* [veracode-research/rogue-jndi - A malicious LDAP server for JNDI injection attacks - javaSerializedData属性方式，不受到codebase信任限制](https://github.com/veracode-research/rogue-jndi)

RMI

* [qtc-de/remote-method-guesser - identify security vulnerabilities on Java RMI endpoints](https://github.com/qtc-de/remote-method-guesser)
* [BishopFox/rmiscout - uses wordlist and bruteforce strategies to enumerate Java RMI functions and exploit RMI parameter unmarshalling vulnerabilities](https://github.com/BishopFox/rmiscout)
* [waderwu/attackRmi - This project uses the socket to send packets directly to attack rmi](https://github.com/waderwu/attackRmi)
* [NickstaDB/BaRMIe - Java RMI enumeration and attack tool](https://github.com/NickstaDB/BaRMIe)

Deserialization

* [Coalfire-Research/java-deserialization-exploits - A collection of curated Java Deserialization Exploits](https://github.com/Coalfire-Research/java-deserialization-exploits)
* [yulate/jdbc-tricks - 《深入JDBC安全：特殊URL构造与不出网反序列化利用技术揭秘》对应研究总结项目 "Deep Dive into JDBC Security: Special URL Construction and Non-Networked Deserialization Exploitation Techniques Revealed" - Research Summary Project](https://github.com/yulate/jdbc-tricks)
* [BeichenDream/InjectJDBC - 通过hook获取DriverManager账号密码](https://github.com/BeichenDream/InjectJDBC)
* [Lotus6/JavaGadgetGenerator - JavaGadgetGenerator 工具，支持 ysoserial，Hessian，字节码，Expr/SSTI，Shiro，JDBC 等 Gadget 生成，封装，混淆，出网延迟探测，内存马注入等 - 代码没开源](https://github.com/Lotus6/JavaGadgetGenerator)
* https://github.com/kezibei/Urldns
* [pedrib/PoC/advisories/Cisco/cisco_ise_rce.md - 包含一个BlazeDS AMF payload生成工具](https://github.com/pedrib/PoC/blob/master/advisories/Cisco/cisco_ise_rce.md)
* [freeFV/ShortPayload - 如何将Java反序列化Payload极致缩小](https://github.com/freeFV/ShortPayload)
* [feihong-cs/jre8u20_gadget - 以一种更简单的方式构造JRE8u20 Gadget](https://github.com/feihong-cs/jre8u20_gadget)
* [genxor/Deserialize - defineClass在反序列化中的利用，2018停更](https://github.com/genxor/Deserialize)
* [potats0/javaSerializationTools - 支持通过JSON数据配置的方式动态生成Java序列化字节码，省去了exp编写人员肉眼分析序列化字节码，同时还可以使用python快速编写出攻击逻辑](https://github.com/potats0/javaSerializationTools)
* [BishopFox/GadgetProbe - Probe endpoints consuming Java serialized objects to identify classes, libraries, and library versions on remote Java classpaths - 修改过的URLDNS payload，可以探测指定的class是否已经加载，并有burpsuite插件](https://github.com/BishopFox/GadgetProbe)
* [frohoff/jdeserialize - a library that interprets Java serialized objects](https://github.com/frohoff/jdeserialize/tree/master/jdeserialize)
* [kantega/notsoserial - Java Agent which mitigates deserialisation attacks by making certain classes unserializable](https://github.com/kantega/notsoserial)
* [JackOfMostTrades/gadgetinspector - A byte code analyzer for finding deserialization gadget chains in Java applications](https://github.com/JackOfMostTrades/gadgetinspector)
* [frohoff/ysoserial - A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization](https://github.com/frohoff/ysoserial)
* [wh1t3p1g/ysomap - 一个更加灵活的框架来扩展反序列化利用链](https://github.com/wh1t3p1g/ysomap)
* [pwntester/SerialKillerBypassGadgetCollection - Collection of bypass gadgets to extend and wrap ysoserial payloads](https://github.com/pwntester/SerialKillerBypassGadgetCollection)
* [mbechler/marshalsec - Java Unmarshaller Security - Turning your data into code execution](https://github.com/mbechler/marshalsec)
* [threedr3am/marshalsec - 一个Java编码、解码漏洞利用工具，加入了Dubbo-Hessian2和Apache Shiro PaddingOracle CBC的exploits](https://github.com/threedr3am/marshalsec)
* [NickstaDB/SerializationDumper - A tool to dump Java serialization streams in a more human readable form](https://github.com/NickstaDB/SerializationDumper)
* [threedr3am/dubbo-exp - Dubbo反序列化一键快速攻击测试工具，支持dubbo协议和http协议，支持hessian反序列化和java原生反序列化](https://github.com/threedr3am/dubbo-exp)
* [Ruil1n/after-deserialization-attack - Java后反序列化漏洞利用思路](https://github.com/Ruil1n/after-deserialization-attack)
* [joaomatosf/JavaDeserH2HC - Sample codes written for the Hackers to Hackers Conference magazine 2017 (H2HC)](https://github.com/joaomatosf/JavaDeserH2HC)
* [feihong-cs/deserizationEcho - 反序列化回显测试代码](https://github.com/feihong-cs/deserizationEcho)
* [pwntester/JRE8u20_RCE_Gadget - Pure JRE 8 RCE Deserialization gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget)

Resources

* [HackJava/HackJava - 《Java安全-只有Java安全才能拯救宇宙》Only Java Security Can Save The Universe](https://github.com/HackJava/HackJava)
* [phith0n/JavaThings - Share Things Related to Java - Java安全漫谈笔记相关内容](https://github.com/phith0n/JavaThings)
* [2021.05.05 - How I Hacked Google App Engine: Anatomy of a Java Bytecode Exploit](https://blog.polybdenum.com/2021/05/05/how-i-hacked-google-app-engine-anatomy-of-a-java-bytecode-exploit.html)
* [2019.01.04 浅析Java序列化和反序列化](https://mp.weixin.qq.com/s/8lkpqHJ_CrRizPDZ38svTg)

Code samples

* [ityouknow/spring-boot-examples - Spring Boot 教程、技术栈示例代码，快速简单上手教程](https://github.com/ityouknow/spring-boot-examples)
* [JavaCodeMing/SpringBoot-Shiro - Spring Boot + Shiro例子](https://github.com/JavaCodeMing/SpringBoot-Shiro)

Expression Language

* [kiegroup/drools - Drools is a rule engine, DMN engine and complex event processing (CEP) engine for Java - 4.1K star，复杂事件处理引擎和条件匹配](https://github.com/kiegroup/drools)

Uncategorized

* https://java-chains.vulhub.org/
* [yzddmr6/Java-Js-Engine-Payloads - 各种JS payload](https://github.com/yzddmr6/Java-Js-Engine-Payloads)
* [kyo-w/router-router - Java web路由内存分析工具](https://github.com/kyo-w/router-router)
* [4ra1n/jar-analyzer - 一个用于分析Jar包的GUI工具，可以用多种方式搜索你想要的信息，自动构建方法调用关系，支持分析Spring框架（A Java GUI Tool for Analyzing Jar）](https://github.com/4ra1n/jar-analyzer)
* [ecbftw/poc/java-python-ftp-injection/ftp-injection-server.py - Java FTP请求CRLF利用，测试无效](https://github.com/ecbftw/poc/blob/master/java-python-ftp-injection/ftp-injection-server.py)
* [f1tz/BCELCodeman - BCEL encode/decode manager for fastjson payloads](https://github.com/f1tz/BCELCodeman)
* [c0ny1/java-object-searcher - java内存对象搜索辅助工具](https://github.com/c0ny1/java-object-searcher)
* [5wimming/gadgetinspector - 利用链、漏洞检测工具](https://github.com/5wimming/gadgetinspector)
* [JReFrameworker/JReFrameworker - A practical tool for bytecode manipulation and creating Managed Code Rootkits (MCRs) in the Java Runtime Environment](https://github.com/JReFrameworker/JReFrameworker)
* [EnigmaBridge/javacard-curated-list - open-source Java Card applets and related applications for cryptographic smartcards](https://github.com/EnigmaBridge/javacard-curated-list)
* [GraxCode/cafecompare - Java code comparison tool (jar / class)](https://github.com/GraxCode/cafecompare)
* [Artemis1029/Java_xmlhack - 帮助java环境下任意文件下载情况自动化读取源码的小工具](https://github.com/Artemis1029/Java_xmlhack)
* [matthiaskaiser/jmet - Java Message Exploitation Tool](https://github.com/matthiaskaiser/jmet)
* [siberas/sjet - siberas JMX exploitation toolkit](https://github.com/siberas/sjet)
* [hengyunabc/dumpclass - Dump classes from running JVM process](https://github.com/hengyunabc/dumpclass)
* [c0d3p1ut0s/java-security-manager-bypass - java security manager bypass的poc - 有博客](https://github.com/c0d3p1ut0s/java-security-manager-bypass)
* [0Kee-Team/JavaProbe - 一款Java应用运行时信息收集工具](https://github.com/0Kee-Team/JavaProbe)
* [feihong-cs/Java-Rce-Echo - Java RCE 回显测试代码](https://github.com/feihong-cs/Java-Rce-Echo)
* [Afant1/RemoteObjectInvocationHandler - bypass JEP290 RaspHook code](https://github.com/Afant1/RemoteObjectInvocationHandler)
* [java-native-access/jna - JNA allows you to call directly into native functions using natural Java method invocation. The Java call looks just like the call does in native code. Most calls require no special handling or configuration; no boilerplate or generated code is required](https://github.com/java-native-access/jna)
* [JetBrains/jediterm - Pure Java Terminal Emulator. Works with SSH and PTY](https://github.com/JetBrains/jediterm)
* [fornwall/jelf - ELF parsing library in java](https://github.com/fornwall/jelf)
* [fuzhengwei/itstack-demo-bytecode - 本专栏主要针对字节码编程系列知识栈进行编写文章学习。在字节码编程方便有三个比较常见的框架；ASM、Javassit、Byte-buddy，他们都可以使用自己的API方式进行字节码的插装，通过这样增强方法的方式就可以和Javaagent结合起来开发非入侵的全链路监控服务，以及做反射、中间件和混淆代码等](https://github.com/fuzhengwei/itstack-demo-bytecode)
* [xiaopan233/Java_agent_without_file - Java agent without file 无文件的Java agent](https://github.com/xiaopan233/Java_agent_without_file)

Resources

* https://potoyang.gitbook.io/spring-in-action-v5/
