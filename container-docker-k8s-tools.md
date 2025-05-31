## Collections

3rdparty lists

* [neargle/my-re0-k8s-security - [WIP] 整理过去的分享，从零开始的Kubernetes攻防 - 2.6K star](https://github.com/neargle/my-re0-k8s-security)
* [wsargent/docker-cheat-sheet - Docker Cheat Sheet](https://github.com/wsargent/docker-cheat-sheet)
* [kabachook/k8s-security - Kubernetes security notes and best practices](https://github.com/kabachook/k8s-security)
* [mhausenblas/k8s-sec - Kubernetes Security from Image Hygiene to Network Policies](https://github.com/mhausenblas/k8s-sec)
* [brant-ruan/awesome-cloud-native-security - awesome resources about cloud native security](https://github.com/brant-ruan/awesome-cloud-native-security)

Post penetration

* [Esonhugh/k8spider - Powerful+Fast+Low Privilege Kubernetes service discovery tools via kubernetes DNS service. Currently supported service ip-port BruteForcing / AXFR Domain Transfer Dump / Coredns WildCard Dump / Pod Verified IP discovery](https://github.com/Esonhugh/k8spider)
* [DataDog/KubeHound - A Kubernetes attack graph tool allowing automated calculation of attack paths between assets in a cluster](https://github.com/DataDog/KubeHound)
* [Metarget/kootkit - k0otkit is a universal post-penetration technique which could be used in penetrations against Kubernetes clusters - 用DaemonSet持久化，用Secret存储payload，用perl + memfd_create实现无文件，修改kube-proxy容器实现隐藏](https://github.com/Metarget/k0otkit)
* [SPuerBRead/shovel - Docker容器逃逸工具（Docker Escape Tools）](https://github.com/SPuerBRead/shovel)
* [cdk-team/CDK - CDK is an open-sourced container penetration toolkit, offering stable exploitation in different slimmed containers without any OS dependency. It comes with penetration tools and many powerful PoCs/EXPs helps you to escape container and takeover K8s cluster easily - 目前最全面的容器工具和漏洞总结，1.8K star](https://github.com/cdk-team/CDK)
  * [tsrc: 红蓝对抗中的云原生漏洞挖掘及利用实录 - neargle、pk编写，比较全面](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)

Uncategorized

* [earthquake/chw00t - Unices chroot breaking tool - 2019停更](https://github.com/earthquake/chw00t)
* [twistlock/whoc - A container image that exfiltrates the underlying container runtime to a remote server - 构建PIE程序替换ld，并在容器启动时候读取/proc/self/exe，最后还原ld并通过curl将runc程序发出，这样就可以获取runc的版本了](https://github.com/twistlock/whoc)
* [ropnop/pentest_charts - Some helpful Helm Charts for pentesters](https://github.com/ropnop/pentest_charts)
* [kubesphere - The container platform tailored for Kubernetes multi-cloud, datacenter, and edge management - 7K star，开发插件非常多](https://github.com/kubesphere/kubesphere)
* [fanux/sealos - 一条命令安装kubernetes，超全版本，支持国产化，生产环境中稳如老狗，99年证书，0依赖，去haproxy keepalived，v1.20支持containerd - 3.2K star](https://github.com/fanux/sealos)
* [BishopFox/badPods - A collection of manifests that will create pods with elevated privileges - 常见k8s提权面，实战基本不会遇到](https://github.com/BishopFox/badPods)
* [talos-systems/talos - a modern OS for Kubernetes](https://github.com/talos-systems/talos)
* [StefanScherer/packer-windows - Windows Templates for Packer: Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, 1909, 2004, Insider with Docker](https://github.com/StefanScherer/packer-windows)
* [inguardians/peirates - Kubernetes Penetration Testing tool](https://github.com/inguardians/peirates)

Exploits

* [quarkslab/kdigger - kdigger is a context discovery tool for Kubernetes penetration testing](https://github.com/quarkslab/kdigger)
* [cyberark/KubiScan - A tool to scan Kubernetes cluster for risky permissions](https://github.com/cyberark/KubiScan)
* [cyberark/kubesploit - Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments - 基于merlin，加了5个容器逃逸的模块，代码在 data/modules/go 目录](https://github.com/cyberark/kubesploit)
* [danielsagi/kube-dnsspoof - A POC for DNS spoofing in kubernetes clusters. Runs with minimum capabilities, on default installations of kuberentes](https://github.com/danielsagi/kube-dnsspoof/)
* [serain/kubelet-anon-rce - Executes commands in a container on a kubelet endpoint that allows anonymous authentication (default)](https://github.com/serain/kubelet-anon-rce)
* [initstring/lxd_root - Linux privilege escalation via LXD - 脚本兼容性有问题，Ubuntu 18.04 不成功](https://github.com/initstring/lxd_root)
* Container Escape
  * [danielsagi/kube-pod-escape - Kubernetes POC for utilizing write mount to /var/log for getting a root on the host](https://github.com/danielsagi/kube-pod-escape)
  * [FSecureLABS/fdpasser - Example of passing file descriptors into a container to perform a privilege escalation on the host](https://github.com/FSecureLABS/fdpasser)

Hardening

* [bytedance/vArmor - vArmor is a cloud native container sandbox based on LSM. It includes multiple built-in protection rules that are ready to use out of the box](https://github.com/bytedance/vArmor)
* [kyverno - Kubernetes Native Policy Management](https://github.com/kyverno/kyverno)
* [DataDog/security-agent-policies/runtime/default.policy - datadog agent默认规则](https://github.com/DataDog/security-agent-policies/blob/master/runtime/default.policy)
* [edgelesssys/constellation - Constellation is the first Confidential Kubernetes. Constellation shields entire Kubernetes clusters from the (cloud) infrastructure using confidential computing](https://github.com/edgelesssys/constellation)
* [neuvector/neuvector - NeuVector Full Lifecycle Container Security Platform delivers the only cloud-native security with uncompromising end-to-end protection from DevOps vulnerability protection to automated run-time security, and featuring a true Layer 7 container firewall](https://github.com/neuvector/neuvector)
  * https://mp.weixin.qq.com/s/aXSA_opN-rV68rnrPO73PA
* [kata-containers/kata-containers - Kata Containers is an open source project and community working to build a standard implementation of lightweight Virtual Machines (VMs) that feel and perform like containers, but provide the workload isolation and security advantages of VMs - 安全容器，1.6K star](https://github.com/kata-containers/kata-containers)
* [google/gvisor - Application Kernel for Containers - 安全容器，11.8K star](https://github.com/google/gvisor)
* [open-policy-agent/opa - An open source, general-purpose policy engine - 5.7K star](https://github.com/open-policy-agent/opa)
* [open-policy-agent/gatekeeper - Policy Controller for Kubernetes - 2.1K star](https://github.com/open-policy-agent/gatekeeper)
* [datreeio/datree - a CLI tool to ensure K8s manifests and Helm charts follow best practices as well as your organization’s policies](https://github.com/datreeio/datree)
* [docker/docker-bench-security - The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production](https://github.com/docker/docker-bench-security)
* [aquasecurity/kube-bench - Checks whether Kubernetes is deployed according to security best practices as defined in the CIS Kubernetes Benchmark](https://github.com/aquasecurity/kube-bench)
* [docker-slim - Don't change anything in your Docker container image and minify it by up to 30x (and for compiled languages even more) making it secure too](https://github.com/docker-slim/docker-slim)

Static analysis

* [P3GLEG/WhaleTail - Program to reverse Docker images into Dockerfiles](https://github.com/P3GLEG/WhaleTail)
* [GoogleContainerTools/container-diff - Diff your Docker containers](https://github.com/GoogleContainerTools/container-diff)
* [wagoodman/dive - A tool for exploring each layer in a docker image](https://github.com/wagoodman/dive)
* [coreos/clair - Vulnerability Static Analysis for Containers](https://github.com/coreos/clair)
* [aquasecurity/trivy - Find vulnerabilities, misconfigurations, secrets, SBOM in containers, Kubernetes, code repositories, clouds and more](https://github.com/aquasecurity/trivy)
* [nccgroup/whalescan - Whalescan is a vulnerability scanner for Windows containers, which performs several benchmark checks, as well as checking for CVEs/vulnerable packages on the container](https://github.com/nccgroup/whalescan)

Auditing & Monitoring

* [paralus/paralus - All-in-one Kubernetes access manager. User-level credentials, RBAC, SSO, audit logs](https://github.com/paralus/paralus)
* [kubesphere/kubeeye - KubeEye aims to find various problems on Kubernetes, such as application misconfiguration, unhealthy cluster components and node problems](https://github.com/kubesphere/kubeeye)
* [twistlock/sa-hunter - Correlates serviceaccounts and pods to the permissions granted to them via rolebindings and clusterrolesbindings](https://github.com/twistlock/sa-hunter)
* [stackrox - The StackRox Kubernetes Security Platform performs a risk analysis of the container environment, delivers visibility and runtime alerts, and provides recommendations to proactively improve security by hardening the environment](https://github.com/stackrox/stackrox)
* [chaitin/veinmind-tools - 长亭科技自研，基于 veinmind-sdk 打造的容器安全工具集 - 内置了不少规则，看着还可以](https://github.com/chaitin/veinmind-tools)
* [armosec/kubescape - the first tool for testing if Kubernetes is deployed securely as defined in Kubernetes Hardening Guidance by to NSA and CISA](https://github.com/armosec/kubescape)
* [brompwnie/botb - A container analysis and exploitation tool for pentesters and engineers](https://github.com/brompwnie/botb)
* [jessfraz/amicontained - Container introspection tool. Find out what container runtime is being used as well as features available - 在容器内枚举权限的工具，如 seccomp/capability/namespace](https://github.com/jessfraz/amicontained)
* [projectcalico/calico - Cloud native networking and network security](https://github.com/projectcalico/calico)
* [Shopify/kubeaudit - helps you audit your Kubernetes clusters against common security controls](https://github.com/Shopify/kubeaudit)
* [aquasecurity/trivy - A Simple and Comprehensive Vulnerability Scanner for Containers, Suitable for CI - 18K star](https://github.com/aquasecurity/trivy)
* [sysdiglabs/kube-psp-advisor - Help building an adaptive and fine-grained pod security policy](https://github.com/sysdiglabs/kube-psp-advisor)
* [aquasecurity/kube-hunter - Hunt for security weaknesses in Kubernetes clusters - 3.3K star](https://github.com/aquasecurity/kube-hunter)
* [nccgroup/kube-auto-analyzer - Kubernetes Auto Analyzer - 停更了](https://github.com/nccgroup/kube-auto-analyzer)
* [cr0hn/dockerscan - Docker security analysis & hacking tools](https://github.com/cr0hn/dockerscan)

Network

* [merbridge - Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge](https://github.com/merbridge/merbridge)

Dockerfile collections

* [vimagick/dockerfiles - A collection of delicious docker recipes ](https://github.com/vimagick/dockerfiles)
* [astj/docker-centos5-vault - A drop-in replacement of centos:5.11 with modified yum repository spec with vault.centos.org](https://github.com/astj/docker-centos5-vault)

## Resources

* [一文深入理解 Kubernetes（腾讯技术工程）](https://mp.weixin.qq.com/s/zmboxeW-vknLKi1IQIxVMQ)
* [Container escape in 2021 - 有CAP_ADMIN权限时的几种逃逸方法](https://conference.hitb.org/hitbsecconf2021sin/materials/D2T2%20-%20Ccntainer%20Escape%20in%202021%20-%20Li%20Qiang.pdf)
* [NIST Special Publication 800-190 - Application Container Security Guide - 2017.09](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
* [国内首个云上容器ATT&CK攻防矩阵发布，阿里云助力企业容器化安全落地](https://developer.aliyun.com/article/765449)
* [BH USA-20 Escaping Virtualized Containers](https://i.blackhat.com/USA-20/Thursday/us-20-Avrahami-Escaping-Virtualized-Containers.pdf)
* [BH USA-20 Defending containers like a ninja](https://i.blackhat.com/USA-20/Wednesday/us-20-Berta-Defending-Containers-Like-A-Ninja-A-Walk-Through-The-Advanced-Security-Features-Of-Docker-And-Kubernetes.pdf)
* [Kubernetes: Master Post - 2019年以及之前的问题汇总](https://blog.carnal0wnage.com/2019/01/kubernetes-master-post.html)
* [Kubernetes and HostPath, a Love-Hate Relationship - k8s路径挂载相关的历史漏洞](https://blog.quarkslab.com/kubernetes-and-hostpath-a-love-hate-relationship.html)