开发者指南
==========

+ [English Version of Contributing Guide](../CONTRIBUTING.md)

目录
----
1. [报告 BUG](#1-报告-bug)
   1. [报告安全漏洞](#11-报告安全漏洞)
   2. [报告崩溃事件](#12-报告崩溃事件)
   3. [报告一般 BUG](#13-报告一般-bug)
   4. [报告 Alibaba Cloud Linux 操作系统 BUG](#14-报告-alibaba-cloud-linux-操作系统-bug)
2. [帮助改进项目](#2-帮助改进项目)
   1. [获取内核源码](#21-获取内核源码)
   2. [构建内核](#22-构建内核)
   3. [提交补丁](#23-提交补丁)

-----------------

## 1. 报告 BUG

参与本项目最直接的方式就是使用 Cloud Kernel 和 Alibaba Cloud Linux 操作系统并向我们报告使用中遇到的 BUG. 不过在提交 BUG 报告之前，需要先了解一些基本原则：

### 1.1 报告安全漏洞

我们欢迎来自安全领域的研究专家向我们提交内核及操作系统方面的漏洞报告，然而我们不鼓励任何人**直接**公开安全漏洞细节。如需报告安全漏洞，烦请发送相关报告至我们的服务邮箱 [alicloud-linux-os@service.alibaba.com](mailto:alibaba-linux-os@service.alibaba.com), 我们会第一时间查收并仔细审阅。

### 1.2 报告崩溃事件

我们深知操作系统和内核的崩溃事件(Kernel Panic)对于任何用户来说都是一个很严重的事件，我们会将此类 BUG 报告提升到高优先级来解决，请在项目的 [issues](https://github.com/alibaba/cloud-kernel/issues) 页面报告此类问题。为了便于我们更好地理解您所碰到的问题，请尽可能包含下列信息：

+ Kdump core 文件或者系统崩溃时的内核栈输出信息；
+ 有可能触发崩溃的嫌疑应用或操作；
+ 如果 Kdump core 或内核栈无法捕捉，至少需要提供内核版本信息。

分析内核崩溃问题极具挑战性，我们鼓励任何尝试帮助复现问题，以推进问题排查的行为。

### 1.3 报告一般 BUG

请在项目的 [issues](https://github.com/alibaba/cloud-kernel/issues) 页面报告此类问题。

### 1.4 报告 Alibaba Cloud Linux 操作系统 BUG

Cloud Kernel 与 Alibaba Cloud Linux 操作系统关系紧密，如果您遇到任何 Alibaba Cloud Linux 操作系统相关的问题，也请在项目的 [issues](https://github.com/alibaba/cloud-kernel/issues) 页面提交 BUG 报告，或者在[邮件列表](MAILLIST.md)及[阿里云开发者论坛](https://bbs.aliyun.com/thread/450.html)参与讨论。

## 2. 帮助改进项目

### 2.1 获取内核源码

在决定参与内核开发之前，建议您先获取内核源码并构建内核。您可以从 [Releases](https://github.com/alibaba/cloud-kernel/releases) 页面下载到稳定版内核的压缩包，然后解压缩到某个目录：

```shell
tar xzf ck-release-7.tar.gz
```

或者您也可以从我们的 Git 仓库 Clone 代码：

```shell
git clone git@github.com:alibaba/cloud-kernel.git
cd cloud-kernel
```

> 您或许已经注意到项目的默认分支并非 `master` 分支而是形如 `ck-4.19.y` 格式的分支。这是由于我们采用了 "rebase" 策略来更新我们的代码，每次从 Upstream LTS 版本同步代码后，我们都会 rebase 到新的代码分支，并将此分支作为新的默认分支。


### 2.2 构建内核

构建内核之前，您需要一个内核配置文件。我们在 `master` 分支提供了一个[默认内核配置文件](config-4.19.y-x86_64)，您只需下载并将其重命名为 `.config`，然后保存到内核源码树的顶层目录下。

```bash
wget https://raw.githubusercontent.com/alibaba/cloud-kernel/master/config-4.19.y-x86_64
cp config-4.19.y-x86_64 cloud-kernel/.config
```

> 请注意，默认内核配置文件是一个精简定制版本，删掉了众多驱动模块，其中就包括存储设备驱动和网卡驱动等。因此您不应该直接将此内核运行于物理机上，否则物理机可能因缺少驱动而无法启动。我们推荐您只在 KVM 虚拟机中运行该内核，或者您确认已自行在非 KVM 平台中启用所需的驱动模块。

假设您已事先安装好所需的工具链，此时您可以开始构建内核了：

```bash
cd cloud-kernel
make oldconfig
make -jN # N 一般是您系统中 CPU 的逻辑核数
make modules -jN
sudo make modules_install
sudo make install
```

接下来，您可以重启并运行您的新内核。重启前请确保您有紧急启动系统的手段，以防新内核无法正常启动。

### 2.3 提交补丁

在您日常使用 Cloud Kernel 过程中，您或许发现了一些内核 BUG，并且找到了修复它的方法。欢迎将修复整理成补丁发送给我们。

Cloud Kernel 的开发和 Linux 内核社区开发模式基本一致，您可以参阅 kernel.org 上的 "[submitting patches guide](https://www.kernel.org/doc/html/latest/process/submitting-patches.html)" 一文，在您制作完补丁之后，您可以将补丁发送到我们的[开发者邮件列表](MAILLIST.md#alibaba-cloud-linux-os-kernel-developers-group)中提交审阅。
