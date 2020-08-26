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

Office

* [debasishm89/OpenXMolar - A MS OpenXML Format Fuzzing Framework - 2018停更](https://github.com/debasishm89/OpenXMolar)

Network

* [denandz/fuzzotron - A TCP/UDP based network daemon fuzzer](https://github.com/denandz/fuzzotron)
* [sogeti-esec-lab/RPCForge - Windows RPC Python fuzzer](https://github.com/sogeti-esec-lab/RPCForge)
* [Cisco-Talos/mutiny-fuzzer - a network fuzzer that operates by replaying PCAPs through a mutational fuzzer](https://github.com/Cisco-Talos/mutiny-fuzzer)
* [andresriancho/websocket-fuzzer - Simple HTML5 WebSocket fuzzer](https://github.com/andresriancho/websocket-fuzzer)
* [nccgroup/wssip - Application for capturing, modifying and sending custom WebSocket data from client to server and vice versa](https://github.com/nccgroup/wssip)

Android

* [ajinabraham/Droid-Application-Fuzz-Framework - Android application fuzzing framework with fuzzers and crash monitor](https://github.com/ajinabraham/Droid-Application-Fuzz-Framework)
* [m-y-mo/android_nfc_fuzzer - a fuzzer that uses libprotobuf-mutator to fuzz the NFC module on an Android device](https://github.com/m-y-mo/android_nfc_fuzzer)

Windows kernel

* [koutto/ioctlbf - Windows Kernel Drivers fuzzer](https://github.com/koutto/ioctlbf)
* [mwrlabs/KernelFuzzer - Cross Platform Kernel Fuzzer Framework](https://github.com/mwrlabs/KernelFuzzer)
* [Cr4sh/ioctlfuzzer - a tool designed to automate the task of searching vulnerabilities in Windows kernel drivers by performing fuzz tests on them](https://github.com/Cr4sh/ioctlfuzzer)
* [mwrlabs/ViridianFuzzer - a kernel driver that make hypercalls, execute CPUID, read/write to MSRs from CPL0](https://github.com/mwrlabs/ViridianFuzzer)
* [hfiref0x/NtCall64 - Windows NT x64 syscall fuzzer](https://github.com/hfiref0x/NtCall64)
* [compsec-snu/razzer - A Kernel fuzzer focusing on race bugs](https://github.com/compsec-snu/razzer)
* [fgsect/unicorefuzz - Fuzzing the Kernel using AFL Unicorn](https://github.com/fgsect/unicorefuzz)
* [IOActive/FuzzNDIS - A Fuzzer for Windows NDIS Drivers OID Handlers](https://github.com/IOActive/FuzzNDIS/)

Linux kernel

* [google/ktsan - KernelThreadSanitizer, a fast data race detector for the Linux kernel ](https://github.com/google/ktsan)
* [sslab-gatech/janus - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://github.com/sslab-gatech/janus)
* [ucsb-seclab/difuze - Fuzzer for Linux Kernel Drivers](https://github.com/ucsb-seclab/difuze)
* [google/syzkaller - an unsupervised, coverage-guided kernel fuzzer](https://github.com/google/syzkaller/)
  * [Using syzkaller to detect programming bugs in the Linux kernel](https://www.collabora.com/news-and-blog/blog/2020/04/17/using-syzkaller-to-detect-programming-bugs-in-linux/)
* [TriforceLinuxSyscallFuzzer - A linux system call fuzzer using TriforceAFL](https://github.com/nccgroup/TriforceLinuxSyscallFuzzer)
* [sslab-gatech/janus - Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://github.com/sslab-gatech/janus)
* [intel/kernel-fuzzer-for-xen-project - VMI Kernel Fuzzer for Xen Project: VM forking, VMI & AFL integration demo](https://github.com/intel/kernel-fuzzer-for-xen-project)
* [0xricksanchez/fisy-fuzz - This is the full file system fuzzing framework that I presented at the Hack in the Box 2020 Lockdown Edition conference in April](https://github.com/0xricksanchez/fisy-fuzz)
* [IntelLabs/kAFL - HW-assisted Feedback Fuzzing for x86 Kernels](https://github.com/IntelLabs/kAFL)
* [ucsb-seclab/difuze - Fuzzer for Linux Kernel Drivers](https://github.com/ucsb-seclab/difuze)
* [google/kmsan - KernelMemorySanitizer, a detector of uses of uninitialized memory in the Linux kernel](https://github.com/google/kmsan)

MacOS kernel

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

WASM

* [pventuzelo/wasm_runtimes_fuzzing - Improving security and resilience of WebAssembly runtimes and parsers using fuzzing](https://github.com/pventuzelo/wasm_runtimes_fuzzing)

PHP

* [nikic/PHP-Fuzzer - Experimental fuzzer for PHP libraries](https://github.com/nikic/PHP-Fuzzer)

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

* [securesystemslab/agamotto - Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints](https://github.com/securesystemslab/agamotto)
* [nautilus-fuzz/nautilus - A grammar based feedback Fuzzer](https://github.com/nautilus-fuzz/nautilus)
* [Cisco-Talos/Barbervisor - Intel x86 bare metal hypervisor for researching snapshot fuzzing ideas](https://github.com/Cisco-Talos/Barbervisor)
* [hgascon/pulsar - Protocol Learning and Stateful Fuzzing](https://github.com/hgascon/pulsar)
* [d0c-s4vage/resmack-fuzz-test - an exploration of a feedback-driven fuzzer](https://gitlab.com/d0c-s4vage/resmack-fuzz-test)
* [HexHive/FuzzGen - a tool for automatically synthesizing fuzzers for complex libraries in a given environment](https://github.com/HexHive/FuzzGen)
* [h0mbre/Fuzzing - ptrace + 内存快照实现fuzz](https://github.com/h0mbre/Fuzzing)
* [s3team/Squirrel - a fuzzer that aims at finding memory corruption issues in database managment systems (DBMSs). It is built on AFL.](https://github.com/s3team/Squirrel)
* [googleprojectzero/TinyInst - A lightweight dynamic instrumentation library](https://github.com/googleprojectzero/TinyInst)
* [fgsect/BaseSAFE - Emulation and Feedback Fuzzing of Firmware with Memory Sanitization](https://github.com/fgsect/BaseSAFE)
* [trailofbits/sienna-locomotive - A user-friendly fuzzing and crash triage tool for Windows](https://github.com/trailofbits/sienna-locomotive)
* [AFLplusplus - afl with community patches](https://github.com/AFLplusplus/AFLplusplus)
* [0xricksanchez/fs-fuzzer - My Material for the HITB presentation](https://github.com/0xricksanchez/fs-fuzzer)
* [seemoo-lab/frankenstein - Broadcom and Cypress firmware emulation for fuzzing and further full-stack debugging](https://github.com/seemoo-lab/frankenstein/)
* [google/FuzzBench - Fuzzer benchmarking as a service](https://github.com/google/FuzzBench)
* [mxmssh/manul - a coverage-guided parallel fuzzer for open-source and blackbox binaries on Windows, Linux and MacOS](https://github.com/mxmssh/manul)
* [atrosinenko/kbdysch - A collection of user-space Linux kernel specific guided fuzzers based on LKL](https://github.com/atrosinenko/kbdysch)
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
* [aoh/radamsa - a general-purpose fuzzer - 这个主要是学习他的mutations.scm，比如 decrement a byte by one](https://gitlab.com/akihe/radamsa)
* [MozillaSecurity/peach - a fuzzing framework which uses a DSL for building fuzzers and an observer based architecture to execute and monitor them](https://github.com/MozillaSecurity/peach)
* [Windows IPC Fuzzing Tools](https://www.nccgroup.trust/us/about-us/resources/windows-ipc-fuzzing-tools/)
* [x41sec/x41-smartcard-fuzzing - X41 Smartcard Fuzzer](https://github.com/x41sec/x41-smartcard-fuzzing)
* [google/BrokenType - TrueType and OpenType font fuzzing toolset](https://github.com/google/BrokenType)
* [mathiasbynens/small - Smallest possible syntactically valid files of different types](https://github.com/mathiasbynens/small)
* [AngoraFuzzer/Angora - a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution](https://github.com/AngoraFuzzer/Angora)
* [gamozolabs/applepie - A hypervisor for fuzzing built with WHVP and Bochs](https://github.com/gamozolabs/applepie)
* [Dongdongshe/neuzz - neural network assisted fuzzer](https://github.com/Dongdongshe/neuzz)
* [google/clusterfuzz - a scalable fuzzing infrastructure which finds security and stability issues in software](https://github.com/google/clusterfuzz)
* [aflnet/aflnet - A Greybox Fuzzer for Network Protocols](https://github.com/aflnet/aflnet)

## Test cases

* [google/fuzzer-test-suite - Set of tests for fuzzing engines](https://github.com/google/fuzzer-test-suite)

## Tutorials

* [The Art of Fuzzing](https://sec-consult.com/wp-content/uploads/files/vulnlab/the_art_of_fuzzing_slides.pdf)
* [A example of fuzzing the ceph filesystem](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/tree/master/docs/harbian_qa/fuzz_testing/syz_for_ceph)
* [google/fuzzing - Tutorials, examples, discussions, research proposals, and other resources related to fuzzing](https://github.com/google/fuzzing)
* [freebuf: 模糊测试工具WinAFL使用指南](https://www.freebuf.com/articles/system/216437.html)
* [lcatro/Source-and-Fuzzing - 一些阅读源码和Fuzzing 的经验,涵盖黑盒与白盒测试](https://github.com/lcatro/Source-and-Fuzzing)
* [k0keoyo/Some-Kernel-Fuzzing-Paper - Some kernel fuzzing paper about windows and linux](https://github.com/k0keoyo/Some-Kernel-Fuzzing-Paper)


