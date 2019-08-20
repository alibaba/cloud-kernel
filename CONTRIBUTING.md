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

The easiest way to participate in contributing to the project is just use Cloud Kernel and Alibaba Cloud Linux OS, then report bugs to us. However, there are some ground rules against special types of bugs when filing a bug.

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

Cloud Kernel has tight connections with Alibaba Cloud Linux OS, if you run into any Alibaba Cloud Linux OS problems, feel free to file a bug report in our project [issues](https://github.com/alibaba/cloud-kernel/issues) page as well, or start a thread in [mailing lists](MAILLIST.md) or in [Alibaba Cloud Developer forum](https://bbs.aliyun.com/thread/450.html).

## 2. Help to improve

### 2.1 Get kernel source

Before you decide to involve in kernel development, you need to get kernel source and build it. You can download a stable release source from [Releases](https://github.com/alibaba/cloud-kernel/releases) page, then extract the source to a directory:

```shell
tar xzf ck-release-7.tar.gz
```

Alternatively, you can use Git to clone from our git repo.

```shell
git clone git@github.com:alibaba/cloud-kernel.git
cd cloud-kernel
```

> You may have noticed that `master` is not the default branch, instead, you would get a branch named like `ck-4.19.y`. This is due to our 'rebase' approach, every time we rebase from an LTS version, a new branch will be created and then be used as the default branch.

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

During your daily using of Cloud Kernel, you might have found some bugs and you are managed to find a way to fix it. So you probably want to propose a patch to us.

It is highly recommeneded to read the [submitting patches guide](https://www.kernel.org/doc/html/latest/process/submitting-patches.html) from kernel.org when proposing your patch. Additionally, we have some special rules in Cloud Kernel development process below:

#### 2.3.1 Rules of Backporting a Upstream Patch

We **never re-invent wheels**. If there is a solution given in upstream kernel, please backport it to Cloud Kernel instead of writing a new one.

Other rules include:

- a) `Keep the original patch format`. If a patch manages to be applied without any modification, you should keep the original author info, one-line subject and codes. You should try to keep original commit log as well, except adding an upstream commit id reference and your own Signed-off-by signature.

- b) `Give the upstream commit id` at the beginning of commit log body. A valid upstream id should be supposed to be permanent, a good example is Linus tree and a bad example would be a maintainer tree, like tip tree. To reference an upstream commit, you could use the following formats:

    ```bash
    commit <full-sha256-id> upstream. # for mainline commits
    commit <full-sha256-id> from xxx branch. # for other branches
    cherry-picked from https://github.com/xxxx/commit/xxxx # a permanent URL
    ```

- c) `Give your own Signed-off-by` at the bottom of commit log body. This is an efficient way to make us know who is doing the backport.

- d) `Minimal dependencies, minimal modifications`. If a patch fails to apply directly, you might need either to bring back extra depended patches, or to modify the codes. If depenencies are clean enough(_clean_ means they would not modify other unrelated part of codes) and in very small amount (like 1 or 2 patches), feel free to bring extra patches and send them out all together; else you should consider a minimal modification on original patch contents.

- e) `Describe your modification` in commit log. If you make any modifications in the patch, please either add one-line comment or append a paragraph to describe the change. An example of one-line comment is as follows:

    ```bash
    # use square brackets and put right above your Signed-off-by line.
    [ Shile: fix following conflicts by adding a dummy argument ]
    Signed-off-by: Shile Zhang <shile.zhang@linux.alibaba.com>
    ```

#### 2.3.2 Rules of Writing and Submitting New Patches

- a) `Upstream First`. If there is no upstream solution available and you have to compose a new fix, please try your best to send it to LKML or other upstream communities for review first. When the patch gets approved by upstream maintainers, you can backport it to Cloud Kernel. One exception is that if it is an emergency fix for a production issue, you could send it out for review ASAP without getting any approvals from upstream.

- b) `Add testcases`. If you describe your test steps and test results in commit log, that would be fantastic.

- c) `Do not hack`. Patches should be as general-purpose as possbile, dirty hacks or workarounds are not recommended. If patches are not gerneal-purpose enough, we would suggest adding a kernel `CONFIG_*` option, boot parameter or /proc /sys tunable interfacecs to make it be able to be switched off.

#### 2.3.3 Others Rules

- a) `Use keywords for large patch series`. Sometimes you send a large patch series that includes 20 patches or more. It is recommended to add a keyword in subject line of each patch. For example, a patch series that enables a new hardware in Cloud Kernel, individual patches are like:

    ```bash
    ACPI/ADXL: Add address translation interface using an ACPI DSM
    EDAC, skx_edac: Delete duplicated code
    <snip>
    intel_rapl: Fix module autoloading issue
    ```

    You could update the subjects with an `ICX: ` keyword prefix to indicate the whole patch series are used for ICX platform enablement, which is like:

    ```bash
    ICX: ACPI/ADXL: Add address translation interface using an ACPI DSM
    ICX: EDAC, skx_edac: Delete duplicated code
    <snip>
    ICX: intel_rapl: Fix module autoloading issue
    ```
