# opensource-fuzzing-tools

A collection of open source fuzzing tools

## Collections

3rd-party lists

* [一系列用于Fuzzing学习的资源汇总](http://www.freebuf.com/articles/rookie/169413.html)
* [bsauce/Some-Papers-About-Fuzzing - 最新顶会fuzz论文分享](https://github.com/bsauce/Some-Papers-About-Fuzzing)

Browser

* [google/domato - DOM fuzzer](https://github.com/google/domato)
  * [Domato Fuzzer's Generation Engine Internals](https://www.sigpwn.io/blog/2018/4/14/domato-fuzzers-generation-engine-internals)
* [blastxiang/lucky-js-fuzz - A web page based fuzzer that generates random JS statements then fuzz in the web-browser](https://github.com/blastxiang/lucky-js-fuzz)
* [attekett/NodeFuzz - a fuzzer harness for web browsers and browser like applications](https://github.com/attekett/NodeFuzz)
* [stephenfewer/grinder - a system to automate the fuzzing of web browsers and the management of a large number of crashes](https://github.com/stephenfewer/grinder)
* [RootUp/BFuzz - Fuzzing Browsers](https://github.com/RootUp/BFuzz)
* [googleprojectzero/fuzzilli - A JavaScript Engine Fuzzer](https://github.com/googleprojectzero/fuzzilli)
* [MozillaSecurity/grizzly - A cross-platform browser fuzzing framework](https://github.com/MozillaSecurity/grizzly)

Network

* [denandz/fuzzotron - A TCP/UDP based network daemon fuzzer](https://github.com/denandz/fuzzotron)
* [sogeti-esec-lab/RPCForge - Windows RPC Python fuzzer](https://github.com/sogeti-esec-lab/RPCForge)
* [Cisco-Talos/mutiny-fuzzer - a network fuzzer that operates by replaying PCAPs through a mutational fuzzer](https://github.com/Cisco-Talos/mutiny-fuzzer)
* [andresriancho/websocket-fuzzer - Simple HTML5 WebSocket fuzzer](https://github.com/andresriancho/websocket-fuzzer)

Kernel

* [koutto/ioctlbf - Windows Kernel Drivers fuzzer](https://github.com/koutto/ioctlbf)
* [mwrlabs/KernelFuzzer - Cross Platform Kernel Fuzzer Framework](https://github.com/mwrlabs/KernelFuzzer)
* [Cr4sh/ioctlfuzzer - a tool designed to automate the task of searching vulnerabilities in Windows kernel drivers by performing fuzz tests on them](https://github.com/Cr4sh/ioctlfuzzer)
* [mwrlabs/ViridianFuzzer - a kernel driver that make hypercalls, execute CPUID, read/write to MSRs from CPL0](https://github.com/mwrlabs/ViridianFuzzer)
* [hfiref0x/NtCall64 - Windows NT x64 syscall fuzzer](https://github.com/hfiref0x/NtCall64)
* [compsec-snu/razzer - A Kernel fuzzer focusing on race bugs](https://github.com/compsec-snu/razzer)
* [fgsect/unicorefuzz - Fuzzing the Kernel using AFL Unicorn](https://github.com/fgsect/unicorefuzz)
* Linux
  * [sslab-gatech/janus - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://github.com/sslab-gatech/janus)
  * [ucsb-seclab/difuze - Fuzzer for Linux Kernel Drivers](https://github.com/ucsb-seclab/difuze)
  * [google/syzkaller - an unsupervised, coverage-guided kernel fuzzer](https://github.com/google/syzkaller/)
  * [TriforceLinuxSyscallFuzzer - A linux system call fuzzer using TriforceAFL](https://github.com/nccgroup/TriforceLinuxSyscallFuzzer)
  * [sslab-gatech/janus - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://github.com/sslab-gatech/janus)
* MacOS
  * [mwrlabs/OSXFuzz - macOS Kernel Fuzzer](https://github.com/mwrlabs/OSXFuzz)
  * [SilverMoonSecurity/PassiveFuzzFrameworkOSX - fuzzing OSX kernel vulnerability based on passive inline hook mechanism in kernel mode](https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX)

Static analyzer

* [NASA-SW-VnV/ikos - Static analyzer for C/C++ based on the theory of Abstract Interpretation](https://github.com/NASA-SW-VnV/ikos)

Symbolic execution

* [julieeen/kleefl - Seeding fuzzers with symbolic execution](https://github.com/julieeen/kleefl)
* [KLEE Symbolic Execution Engine](http://klee.github.io/)
* [RUB-SysSec/syntia - Program synthesis based deobfuscation framework for the USENIX 2017 paper "Syntia: Synthesizing the Semantics of Obfuscated Code"](https://github.com/RUB-SysSec/syntia)
* [dwrensha/seer - symbolic execution engine for Rust](https://github.com/dwrensha/seer)
* [palkeo - Symbolic execution tool and vulnerability scanner for the Ethereum Virtual Machine](https://github.com/palkeo/pakala)

Coverage tools

* [gamozolabs/mesos - Binary coverage tool without binary modification for Windows](https://github.com/gamozolabs/mesos)
* [googleprojectzero/CompareCoverage - Clang instrumentation module for tracing variable and buffer comparisons in C/C++ and saving the coverage data to .sancov files](https://github.com/googleprojectzero/CompareCoverage)

Java

* [Barro/java-afl - Binary rewriting approach with fork server support to fuzz Java applications with afl-fuzz](https://github.com/Barro/java-afl)
* [rohanpadhye/jqf - Coverage-guided semantic fuzzing for Java](https://github.com/rohanpadhye/jqf)

Dotnet

* [jakobbotsch/Fuzzlyn - Fuzzer for the .NET toolchains](https://github.com/jakobbotsch/Fuzzlyn)
* [debasishm89/dotNetFuzz - A quick and dirty .NET "Deserialize_*" fuzzer based on James Forshaw's (@tiraniddo) DotNetToJScript](https://github.com/debasishm89/dotNetFuzz)

Golang

* [Google/gofuzz - Fuzz testing for go](https://github.com/Google/gofuzz)

ActiveX

* [CERTCC-Vulnerability-Analysis/dranzer - a tool that enables users to examine effective techniques for fuzz testing ActiveX controls](https://github.com/CERTCC-Vulnerability-Analysis/dranzer)

Uncategorized

* [RUB-SysSec/redqueen - Fuz­zing with In­put-to-Sta­te Cor­re­spon­dence](https://github.com/RUB-SysSec/redqueen)
* [d0c-s4vage/gramfuzz - a grammar-based fuzzer that lets one define complex grammars to generate text and binary data formats](https://github.com/d0c-s4vage/gramfuzz)
* [RUB-SysSec/antifuzz - Impeding Fuzzing Audits of Binary Executables](https://github.com/RUB-SysSec/antifuzz)
* [nccgroup/fuzzowski - the Network Protocol Fuzzer that we will want to use](https://github.com/nccgroup/fuzzowski)
* [rk700/uniFuzzer - A fuzzing tool for closed-source binaries based on Unicorn and LibFuzzer](https://github.com/rk700/uniFuzzer)
* [microsoft/lain - A fuzzer framework built in Rust](https://github.com/microsoft/lain)
* [SkyLined/BugId - Detect, analyze and uniquely identify crashes in Windows applications](https://github.com/SkyLined/BugId)
* [mxmssh/drAFL - AFL + DynamoRIO = fuzzing binaries with no source code on Linux](https://github.com/mxmssh/drAFL)
* [google/graphicsfuzz - A testing framework for automatically finding and simplifying bugs in graphics shader compilers](https://github.com/google/graphicsfuzz)
* [IOActive/XDiFF - Extended Differential Fuzzing Framework](https://github.com/IOActive/XDiFF)
* [renatahodovan/fuzzinator - Fuzzinator Random Testing Framework](https://github.com/renatahodovan/fuzzinator)
* [google/honggfuzz - Security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (software- and hardware-based)](https://github.com/google/honggfuzz)
* [AFL - american fuzzy lop](http://lcamtuf.coredump.cx/afl/)
  * [ivanfratric/winafl - A fork of AFL for fuzzing Windows binaries](https://github.com/ivanfratric/winafl)
  * [wmliang/pe-afl - combines static binary instrumentation on PE binary and WinAFL](https://github.com/wmliang/pe-afl)
  * [vanhauser-thc/AFLplusplus - afl 2.53b with community patches, AFLfast power schedules, qemu 3.1 upgrade + laf-intel support, MOpt mutators, InsTrim instrumentation, unicorn_mode and a lot more!](https://github.com/vanhauser-thc/AFLplusplus)
* [nccgroup/TriforceAFL - AFL/QEMU fuzzing with full-system emulation](https://github.com/nccgroup/TriforceAFL)
* [llvm - libFuzzer – a library for coverage-guided fuzz testing](http://llvm.org/docs/LibFuzzer.html)
* [dekimir/RamFuzz - Combining Unit Tests, Fuzzing, and AI](https://github.com/dekimir/RamFuzz)
* [google/oss-fuzz - continuous fuzzing of open source software](https://github.com/google/oss-fuzz)
* [aoh/radamsa - a general-purpose fuzzer](https://github.com/aoh/radamsa)
* [MozillaSecurity/peach - a fuzzing framework which uses a DSL for building fuzzers and an observer based architecture to execute and monitor them](https://github.com/MozillaSecurity/peach)
* [Windows IPC Fuzzing Tools](https://www.nccgroup.trust/us/about-us/resources/windows-ipc-fuzzing-tools/)
* [x41sec/x41-smartcard-fuzzing - X41 Smartcard Fuzzer](https://github.com/x41sec/x41-smartcard-fuzzing)
* [google/BrokenType - TrueType and OpenType font fuzzing toolset](https://github.com/google/BrokenType)
* [mathiasbynens/small - Smallest possible syntactically valid files of different types](https://github.com/mathiasbynens/small)
* [AngoraFuzzer/Angora - a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution](https://github.com/AngoraFuzzer/Angora)
* [gamozolabs/applepie - A hypervisor for fuzzing built with WHVP and Bochs](https://github.com/gamozolabs/applepie)
* [Dongdongshe/neuzz - neural network assisted fuzzer](https://github.com/Dongdongshe/neuzz)
* [google/clusterfuzz - a scalable fuzzing infrastructure which finds security and stability issues in software](https://github.com/google/clusterfuzz)

## Test cases

* [google/fuzzer-test-suite - Set of tests for fuzzing engines](https://github.com/google/fuzzer-test-suite)

## Tutorials

* [The Art of Fuzzing](https://sec-consult.com/wp-content/uploads/files/vulnlab/the_art_of_fuzzing_slides.pdf)
* [A example of fuzzing the ceph filesystem](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/tree/master/docs/harbian_qa/fuzz_testing/syz_for_ceph)
* [google/fuzzing - Tutorials, examples, discussions, research proposals, and other resources related to fuzzing](https://github.com/google/fuzzing)
* [freebuf: 模糊测试工具WinAFL使用指南](https://www.freebuf.com/articles/system/216437.html)
* [lcatro/Source-and-Fuzzing - 一些阅读源码和Fuzzing 的经验,涵盖黑盒与白盒测试](https://github.com/lcatro/Source-and-Fuzzing)


