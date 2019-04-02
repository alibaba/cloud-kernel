Contributing Guide
==================

+ [中文版开发者指南](zh/CONTRIBUTING.md)

Table of Contents
-----------------
1. [Report bugs](#1-report-bugs)
   1. [Report security issues](#11-report-security-issues)
   2. [Report crash issues](#12-report-crash-issues)
   3. [Report general issues](#13-report-general-issues)
   4. [Report Alibaba Cloud Linux OS issues](#14-report-alibaba-cloud-linux-os-issues)
2. [Help to improve](#2-help-to-improve)
   1. [Get kernel source](#21-get-kernel-source)
   2. [Build kernel](#22-build-kernel)
   3. [Propose a patch](#23-propose-a-patch)

-----------------

## 1. Report Bugs

The easiest way to participate in contributing to the project is just use ALK and Alibaba Cloud Linux OS, then report bugs to us. However, there are some ground rules against special types of bugs when filing a bug.

### 1.1 Report security issues

We welcome reports from security researchers and experts about possible security vulnerabilities with our kernel and operating system, however we discourage anyone to spread security issue details. To report a security issue, please send a private email to [alicloud-linux-os@service.alibaba.com](mailto:alibaba-linux-os@service.alibaba.com), we do appreciate it and will review it carefully at one.

### 1.2 Report crash issues

Kernel panic and system crash is critical to any users, we would raise priority against such bug reports, please file bug reports in our project [issues](https://github.com/alibaba/cloud-kernel/issues) page, in order to get better understanding of your problem, please include the following information as much as possible:

+ Kdump core or kernel stack trace when crashed;
+ Suspicious applications or operations that trigger the crash;
+ Kernel version if kdump core or full kernel stack trace not provided.

Digging into a crash issue is always a difficult thing, we do thank to anyone who is willing to help with reproducing the crashes.

### 1.3 Report general issues

Feel free to file bug reports in our project [issues](https://github.com/alibaba/cloud-kernel/issues) page.

### 1.4 Report Alibaba Cloud Linux OS issues

ALK has tight connections with Alibaba Cloud Linux OS, if you run into any Alibaba Cloud Linux OS problems, feel free to file a bug report in our project [issues](https://github.com/alibaba/cloud-kernel/issues) page as well, or start a thread in [mailing lists](MAILLIST.md) or in [Alibaba Cloud Developer forum](https://bbs.aliyun.com/thread/450.html).

## 2. Help to improve

### 2.1 Get kernel source

Before you decide to involve in kernel development, you need to get kernel source and build it. You can download a stable release source from [Releases](https://github.com/alibaba/cloud-kernel/releases) page, then extract the source to a directory:

```shell
tar xzf alk-release-7.tar.gz
```

Alternatively, you can use Git to clone from our git repo.

```shell
git clone git@github.com:alibaba/cloud-kernel.git
cd cloud-kernel
```

> You may have noticed that `master` is not the default branch, instead, you would get a branch named like `alk-4.19.y`. This is due to our 'rebase' approach, every time we rebase from an LTS version, a new branch will be created and then be used as the default branch.

### 2.2 Build kernel

Before building the kernel, you will need a kernel config file. Here we provide a [default kernel config](config-4.19.y-x86_64) in `master` branch, just fetch it and rename to `.config`, then copy it to the top of kernel source directory.

```bash
wget https://raw.githubusercontent.com/alibaba/cloud-kernel/master/config-4.19.y-x86_64
cp config-4.19.y-x86_64 cloud-kernel/.config
```

> The default kernel config is a simplified and customized version, which cuts numerous driver modules, like storage drivers, network drivers, etc. Hence, you should not run the kernel directly on a physical machine, otherwise the system would probably fail to boot. It is recommended that you run the kernel in KVM guests only, unless you are pretty sure required kernel drivers have enabled in your config.

Now you can start your build, presuming you have already installed all required toolchains, then execute:

```bash
cd cloud-kernel
make oldconfig
make -jN # N normally refers to the CPU core numbers on the system
make modules -jN
sudo make modules_install
sudo make install
```

Next, you can just reboot and run into the new kernel. Please make sure you have an emergency boot method deployed in case that the kernel fails to boot.

### 2.3 Propose a patch

During your daily using of ALK, you might have found some bugs and you are managed to find a way to fix it. So you probably want to propose a patch to us.

You can follow the [submitting patches guide from kernel.org](https://www.kernel.org/doc/html/latest/process/submitting-patches.html), when your code is ready, you can just subscribe to our [developer's mailing list](MAILLIST.md#alibaba-cloud-linux-os-kernel-developers-group) and send the patch to us.
