# opensource-docker-tools

A collection of open source docker tools

## Collections

3rdparty lists

* [wsargent/docker-cheat-sheet - Docker Cheat Sheet](https://github.com/wsargent/docker-cheat-sheet)
* [kabachook/k8s-security - Kubernetes security notes and best practices](https://github.com/kabachook/k8s-security)
* [mhausenblas/k8s-sec - Kubernetes Security from Image Hygiene to Network Policies](https://github.com/mhausenblas/k8s-sec)

Uncategorized

* [brant-ruan/awesome-cloud-native-security - awesome resources about cloud native security](https://github.com/brant-ruan/awesome-cloud-native-security)
* [fanux/sealos - 一条命令安装kubernetes，超全版本，支持国产化，生产环境中稳如老狗，99年证书，0依赖，去haproxy keepalived，v1.20支持containerd - 3.2K star](https://github.com/fanux/sealos)
* [BishopFox/badPods - A collection of manifests that will create pods with elevated privileges - 常见k8s提权面，实战基本不会遇到](https://github.com/BishopFox/badPods)
* [talos-systems/talos - a modern OS for Kubernetes](https://github.com/talos-systems/talos)
* [StefanScherer/packer-windows - Windows Templates for Packer: Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, 1909, 2004, Insider with Docker](https://github.com/StefanScherer/packer-windows)
* [Xyntax/CDK - an open-sourced container penetration toolkit, designed for offering stable exploitation in different slimmed containers without any OS dependency. It comes with useful net-tools and many powerful PoCs/EXPs helps you to escape container and takeover K8s cluster easily](https://github.com/Xyntax/CDK)
* [inguardians/peirates - Kubernetes Penetration Testing tool](https://github.com/inguardians/peirates)
* [brompwnie/botb - A container analysis and exploitation tool for pentesters and engineers](https://github.com/brompwnie/botb)

Exploits

* [cyberark/kubesploit - Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments - 基于merlin，加了5个容器逃逸的模块，代码在 data/modules/go 目录](https://github.com/cyberark/kubesploit)
* [danielsagi/kube-dnsspoof - A POC for DNS spoofing in kubernetes clusters. Runs with minimum capabilities, on default installations of kuberentes](https://github.com/danielsagi/kube-dnsspoof/)
* [serain/kubelet-anon-rce - Executes commands in a container on a kubelet endpoint that allows anonymous authentication (default)](https://github.com/serain/kubelet-anon-rce)
* [initstring/lxd_root - Linux privilege escalation via LXD - 脚本兼容性有问题，Ubuntu 18.04 不成功](https://github.com/initstring/lxd_root)
* Container Escape
  * [danielsagi/kube-pod-escape - Kubernetes POC for utilizing write mount to /var/log for getting a root on the host](https://github.com/danielsagi/kube-pod-escape)
  * [FSecureLABS/fdpasser - Example of passing file descriptors into a container to perform a privilege escalation on the host](https://github.com/FSecureLABS/fdpasser)

Hardening

* [docker/docker-bench-security - The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production](https://github.com/docker/docker-bench-security)
* [aquasecurity/kube-bench - Checks whether Kubernetes is deployed according to security best practices as defined in the CIS Kubernetes Benchmark](https://github.com/aquasecurity/kube-bench)
* [docker-slim - Don't change anything in your Docker container image and minify it by up to 30x (and for compiled languages even more) making it secure too](https://github.com/docker-slim/docker-slim)

Static analysis

* [P3GLEG/WhaleTail - Program to reverse Docker images into Dockerfiles](https://github.com/P3GLEG/WhaleTail)
* [GoogleContainerTools/container-diff - Diff your Docker containers](https://github.com/GoogleContainerTools/container-diff)
* [wagoodman/dive - A tool for exploring each layer in a docker image](https://github.com/wagoodman/dive)
* [coreos/clair - Vulnerability Static Analysis for Containers](https://github.com/coreos/clair)
* [nccgroup/whalescan - Whalescan is a vulnerability scanner for Windows containers, which performs several benchmark checks, as well as checking for CVEs/vulnerable packages on the container](https://github.com/nccgroup/whalescan)

Auditing & Monitoring

* [aquasecurity/tracee - Container and system event tracing using eBPF](https://github.com/aquasecurity/tracee)
* [brompwnie/botb - A container analysis and exploitation tool for pentesters and engineers](https://github.com/brompwnie/botb)
* [jessfraz/amicontained - Container introspection tool. Find out what container runtime is being used as well as features available - 在容器内枚举权限的工具，如 seccomp/capability/namespace](https://github.com/jessfraz/amicontained)
* [falcosecurity/falco - Container Native Runtime Security](https://github.com/falcosecurity/falco)
* [projectcalico/calico - Cloud native networking and network security](https://github.com/projectcalico/calico)
* [Shopify/kubeaudit - helps you audit your Kubernetes clusters against common security controls](https://github.com/Shopify/kubeaudit)
* [aquasecurity/trivy - A Simple and Comprehensive Vulnerability Scanner for Containers, Suitable for CI](https://github.com/aquasecurity/trivy)
* [sysdiglabs/kube-psp-advisor - Help building an adaptive and fine-grained pod security policy](https://github.com/sysdiglabs/kube-psp-advisor)
* [aquasecurity/kube-hunter - Hunt for security weaknesses in Kubernetes clusters](https://github.com/aquasecurity/kube-hunter)
* [nccgroup/kube-auto-analyzer - Kubernetes Auto Analyzer - 停更了](https://github.com/nccgroup/kube-auto-analyzer)
* [cr0hn/dockerscan - Docker security analysis & hacking tools](https://github.com/cr0hn/dockerscan)
* [arminc/clair-scanner - Docker containers vulnerability scan](https://github.com/arminc/clair-scanner)

Dockerfile collections

* [vimagick/dockerfiles - A collection of delicious docker recipes ](https://github.com/vimagick/dockerfiles)
* [astj/docker-centos5-vault - A drop-in replacement of centos:5.11 with modified yum repository spec with vault.centos.org](https://github.com/astj/docker-centos5-vault)

## Resources

* [NIST Special Publication 800-190 - Application Container Security Guide - 2017.09](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
* [国内首个云上容器ATT&CK攻防矩阵发布，阿里云助力企业容器化安全落地](https://developer.aliyun.com/article/765449)
* [BH USA-20 Escaping Virtualized Containers](https://i.blackhat.com/USA-20/Thursday/us-20-Avrahami-Escaping-Virtualized-Containers.pdf)
* [BH USA-20 Defending containers like a ninja](https://i.blackhat.com/USA-20/Wednesday/us-20-Berta-Defending-Containers-Like-A-Ninja-A-Walk-Through-The-Advanced-Security-Features-Of-Docker-And-Kubernetes.pdf)



