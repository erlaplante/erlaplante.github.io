---
title: Linux PrivEsc
date: 2026-05-18 00:00:00 -0800
categories: [CVE]
tags: [cve-2026-31431,cve-2026-43284,cve-2026-43500,cve-2026-46300,linux,copy fail,dirty frag,fragnesia,docker,ebpf,tetragon]
description: Discuss methods to prevent some of the recent Linux local privilege escalation exploits using eBFP with Tetragon.
image:
  path: https://i.postimg.cc/HsxC9RNn/linux-priv-esc.png
---

### Overview

In the wake of multiple recent Linux privilege escalation exploits and CVEs I go over my experience using Tetragon as a prevention tool. It was fairly simple to setup and the policy options seem capable of allowing quite a bit of granularity across kernel events using YAML files. In the future I would like to test it more with multiple containers and in a Kubernetes environment.

### Copy Fail

There are many interesting aspects of this vulnerability, the [announcement page](https://copy.fail/) along with the more detailed write up from Xint cover it well. Their one sentence description explains enough to help understand the preventive measure I discuss later, "An unprivileged local user can write 4 controlled bytes into the page cache of any readable file on a Linux system, and use that to gain root."[^1] Its PoC is a small python script, I agree however, with 0xdf's point that it is quite obfuscated and appreciate his [deobfuscated version](https://github.com/0xdf223/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp_deobfuscated.py). In an accompanying video 0xdf also breaks down the ELF binary from the original PoC [hex](https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py#L8) which is used as the shellcode to execute `/bin/sh`.

The readable content can also be revealed using CyberChef:

![image](https://i.postimg.cc/BQnBQ9hy/linux-priv-esc-copyfail-hex.png){: width='1522' height='387'}

In cases where you cannot apply the respective kernel distribution patch or some form of mitigation I wanted to explore other options. I've been interested in learning more about eBPF and discovered that Tetragon is eBPF based and built for security detection and prevention purposes. eBPF allows for safely extending kernel capabilities in a Just-in-Time manner. Due to these recent CVEs abusing functionality at the kernel level it seemed fitting to see what was possible from a defensive perspective at the kernel.

#### Tetragon (Setup)

To test these exploits I used a fresh install (as of about a week ago) from Debain's download page on VirtualBox:

![image](https://i.postimg.cc/rFpf1QNs/linux-priv-esc-uname.png){: width='905' height='232'}

I [installed Docker](https://docs.docker.com/engine/install/debian/#install-using-the-repository) after following Tetragon's quick install instructions to then run it in a privileged container:

```bash
docker run -d --name tetragon --rm --pull always \
    --pid=host --cgroupns=host --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon:v1.7.0
```

After the container is running the below command will allow visibility into a "compact" (easily readable) version of logs. Events will stream in real-time to standard out. The full logs in json format would likely be used, forwarded, etc. in production.

```bash
docker exec tetragon tetra getevents -o compact
```

#### Tetragon (Prevention)

When running the exploit with no preventive policy in place these were the results, python execution and corresponding Tetragon events respectively:

![image](https://i.postimg.cc/ZqfpMHtq/linux-priv-esc-cf-py-init.png){: width='712' height='86'}

![image](https://i.postimg.cc/5yzzjMHX/linux-priv-esc-cf-tetra-init.png){: width='828' height='490'}

`net-pf-38` refers to the AF_ALG socket that allows user access to the Linux crypto processes. This is the exploit entry point for the vulnerable crypto features targeted to eventually overwrite `su`. The write-up's remediation guidance mentions "For immediate mitigation, block AF_ALG socket creation via seccomp or blacklist the algif_aead module".[^2] I used Gemini to help write the Tetragon policies, this one blocks the AF_ALG socket:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-copy-fail-socket"
spec:
  kprobes: # Use Kernel Probes to insert eBPF program into function
    - call: "__x64_sys_socket" # Socket creation
      syscall: true
      args: # Portion of function to look at
        - index: 0
          type: "int" # The domain/address family
      selectors:
        - matchArgs: # Define policy match criteria
            - index: 0
              operator: "Equal"
              values:
                - "38" # Value in Linux kernel for AF_ALG/crypto sockets
          matchActions:
            - action: Sigkill # Kill the process immediately
```
To get this Tracing Policy enforced I placed it in a `policies` directory on the host and re-ran the container with the added line 4 to map a volume:

```bash
docker run -d --name tetragon --rm --pull always        \
    --pid=host --cgroupns=host --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    -v $(pwd)/policies:/policies                        \
    quay.io/cilium/tetragon:v1.7.0
```

Then added the policy by name on the container and verified it showed as enabled and enforced with the list command.

```bash
docker exec tetragon tetra tracingpolicy add /policies/block-copy-fail.yaml
docker exec tetragon tetra tracingpolicy list
```
These were the results with the policy in place:

![image](https://i.postimg.cc/7ZVd65TP/linux-priv-esc-cf-py-prevent.png){: width='482' height='67'}

![image](https://i.postimg.cc/Vvq4Vhqv/linux-priv-esc-cf-tetra-prevent.png){: width='726' height='135'}

### Dirty Frag

The pair of vulnerabilities for Dirty Frag, CVE-2026-43284 and CVE-2026-43500, were publicly reported about a week after Copy Fail. The scope is similar across Linux distributions if combined, as they are in the exploit PoC. The write up also mentions similarities to Copy Fail, specifically the 43284 (ESP) flaw targets eventual untrusted user input similarly to overwrite `su`. The exploit PoC is much lengthier than Copy Fail's but it's also commented quite well and also includes a technical write up. While they are similar to Copy Fail the methods used for the exploits are different and require different mitigations.

#### Tetragon (Prevention)

The prevention Tracing Policies used for each of the Dirty Frag CVEs each target specific socket creations. These could/should be modified as needed if legitimate services break and those could be explicitly allowed.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-dirty-frag-esp"
spec:
  kprobes:
    - call: "__x64_sys_socket"
      syscall: true
      args:
        - index: 0
          type: "int" # The domain/address family
        - index: 2
          type: "int" # Protocol
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "16" # AF_NETLINK
            - index: 2
              operator: "Equal"
              values:
                - "6"  # NETLINK_XFRM
          matchActions:
            - action: Sigkill # Kill the process immediately
```

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-dirty-frag-rxrpc"
spec:
  kprobes:
    - call: "__x64_sys_socket"
      syscall: true
      args:
        - index: 0
          type: "int" # The domain/address family
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "33" # AF_RXRPC
          matchActions:
            - action: Sigkill # Kill the process immediately
```

To compare differences these were the compact events with the Copy Fail and just the RxRPC Tracing Policies in place. The pattern is similar to Copy Fail but with the AF_ALG calls absent:

![image](https://i.postimg.cc/DfxzFL2F/linux-priv-esc-df-rxrpc-pol.png){: width='572' height='115'}

![image](https://i.postimg.cc/pX9PHSGF/linux-priv-esc-df-rxrpc-pol-tetra.png){: width='919' height='719'}

When running the Dirty Frag exploit with just the ESP policy in place the initial socket is killed and it moves on to the RxRPC path to patch `/etc/passwd`. I had to disable the Copy Fail prevention policy otherwise after Stage 2a of the exploit a socket creation for AF_ALG/net-pf-38 gets killed.

![image](https://i.postimg.cc/d1QHGLLH/linux-priv-esc-df-esp-pol.png){: width='936' height='938'}

![image](https://i.postimg.cc/yxgTT9Br/linux-priv-esc-df-esp-pol-tetra.png){: width='1566' height='1113'}

To confirm, with both policies enabled each escalation attempt is thwarted:

![image](https://i.postimg.cc/fbN9wL2d/linux-priv-esc-df-prevent.png){: width='448' height='110'}

![image](https://i.postimg.cc/VL0rnM2y/linux-priv-esc-df-tetra-prevent.png){: width='634' height='377'}

### Fragnesia

Roughly a week after Dirty Frag was made public Fragnesia was discovered, it's similar to Dirty Frag in that it exploits the XFRM-ESP crypto system. Due to the similarities the prevention measures are the same as Dirty Frag. When I tested however, my relatively fresh install of Debian (6.12.73) was not affected. I had an older Ubuntu VM (6.8.0) that I tested on though which was vulnerable, these were the initial results when running Tetragon for visibility into its initial PoC exploit:

![image](https://i.postimg.cc/J0SMQtvR/linux-priv-esc-fragnesia.png){: width='898' height='566'}

I was able to confirm the Dirty Frag ESP Tracing Policy prevented the exploit from escalating privileges.

### References
- [Copy Fail: 732 Bytes to Root on Every Major Linux Distribution.](https://xint.io/blog/copy-fail-linux-distributions)
- [NIST CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [0xdf Copy Fail Explained](https://www.youtube.com/watch?v=wQ914geKOcw)
- [Dirty Frag](https://github.com/V4bel/dirtyfrag)
- [NIST CVE-2026-43284](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- [NIST CVE-2026-43500](https://nvd.nist.gov/vuln/detail/CVE-2026-43500)
- [0xdf Dirty Frag Explained](https://www.youtube.com/watch?v=B5eUI_e7iwE)
- [Fragnesia](https://github.com/v12-security/pocs/tree/main/fragnesia)
- [What is eBPF?](https://ebpf.io/what-is-ebpf/)
- [Tetragon Tracing Policy Example](https://tetragon.io/docs/concepts/tracing-policy/example/)

#### Footnotes
[^1]: [https://copy.fail/#faq (What is Copy Fail in one sentence?)](https://copy.fail/#faq)
[^2]: [https://xint.io/blog/copy-fail-linux-distributions#remediation-7](https://xint.io/blog/copy-fail-linux-distributions#remediation-7)
