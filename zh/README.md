阿里云 Linux 内核 (Alibaba Cloud Linux Kernel)
==============================================

导航 | [English Version](../README.md) | [Alibaba Cloud Linux 操作系统](os.md) | [开发者指南](CONTRIBUTING.md) | [致谢](CREDITS.md)

目录
----
1. [阿里云 Linux 内核是什么](#1-阿里云-linux-内核是什么)
2. [快速运行指南](#2-快速运行指南j)
   1. [运行预编译二进制内核包(推荐)](#21-运行预编译二进制内核包推荐)
   2. [从源码编译内核](#22-从源码编译内核)
3. [参与本项目](#3-参与本项目)
4. [致谢](#4-致谢)
5. [许可证](#5-许可证)
6. [联系我们](#6-联系我们)

---------------------------------


## 1. 阿里云 Linux 内核是什么

阿里云 Linux 内核 (Alibaba Cloud Linux Kernel, ALK) 是由阿里巴巴操作系统团队（原淘宝内核组）开发的一款定制优化版的内核产品，默认运行在带 Alibaba Cloud Linux 2 操作系统（即 Aliyun Linux 2）的阿里云 ECS 产品中。在 ALK 中实现了若干针对阿里云基础设施和产品而优化的特性和改进功能，旨在提高阿里云客户的使用体验。

与其他 Linux 内核产品类似，ALK 理论上可以运行于几乎所有常见的 Linux 发行版中。为了获得更好的功能、性能和稳定性，我们强烈建议您将其运行在带 Alibaba Cloud Linux 2 的阿里云 ECS 实例中。

如需了解 Alibaba Cloud Linux 2 操作系统，请访问[此链接](os.md)。

## 2. 快速运行指南

想要使用 ALK，您既可以运行预编译的二进制内核包，也可以从源码编译内核。请注意我们提供的默认内核配置文件是为阿里云 ECS 实例定制的版本，如果您想要将内核运行于非 ECS 平台上，您需要自行打开相关的内核模块开关并且重新编译内核。

### 2.1 运行预编译二进制内核包(推荐)

首选方案是从 YUM 源安装：

+ 第一步，新建一个 YUM 仓库文件：

```shell
sudo vim /etc/yum.repos.d/alinux-2.1903-plus.repo
```

+ 第二步，填入 repo 信息：

```shell
[plus]
name=Alibaba Cloud Linux 2.1903 Plus Software Collections
baseurl=http://mirrors.aliyun.com/alinux/2.1903/plus/x86_64/
enabled=1
gpgcheck=1
gpgkey=http://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
```

+ 第三步，安装内核：

```shell
sudo yum install -y kernel kernel-devel kernel-headers
```

+ 第四步，重启并使用 ALK.

### 2.2 从源码编译内核

+ 第一步，从以下两种途径之一获取 ALK 源码：
  + 从 [Releases](https://github.com/alibaba/cloud-kernel/releases) 页面获取最新的稳定版内核代码压缩包，并解压到当前目录；
  + 或者从项目 Git 树 Clone 代码： `git clone git@github.com:alibaba/cloud-kernel.git`.

+ 第二步，从 `master` 分支获取[默认内核配置文件](config-4.19.y-x86_64)，重命名为 `.config`, 并复制到源码树的顶层目录下；

+ 第三步，通过下列命令编译并安装内核：

```shell
make oldconfig
make -jN # N normally refers to the CPU core numbers on the system
make modules -jN
sudo make modules_install
sudo make install
```

+ 第四步，重启并使用 ALK.

## 3. 参与本项目

参与 ALK 项目的方式有很多，具体信息可以从 [CONTRIBUTING](CONTRIBUTING.md) 页面获取。

## 4. 致谢

ALK 和 Alibaba Cloud Linux OS 项目是“站在巨人的肩膀上”且聚合了阿里巴巴集团内外众多个人贡献者和团队开发者之力完成的项目。致谢名单可以在 [CREDITS](CREDITS.md) 页面获取，我们也会不断更新该名单。此外，我们需要特别致谢下列项目：

+ [CentOS project](https://www.centos.org/);
+ [Clear Linux project](https://clearlinux.org/);
+ [Intel 0-Day (LKP) project](https://01.org/lkp);
+ [Kata Containers project](https://katacontainers.io/);
+ [Linux kernel project](https://www.kernel.org/).

## 5. 许可证

我们和上游社区使用同样的许可证，请参阅 [COPYING](COPYING) 文件。

## 6. 联系我们

您可以通过下列方式与我们取得联系：

+ 加入[邮件列表](MAILLIST.md)参与讨论；
+ 加入[开发者论坛](https://bbs.aliyun.com/thread/450.html)参与讨论；
+ 或者可以给我们发邮件：[alicloud-linux-os@service.alibaba.com](mailto:alicloud-linux-os@service.alibaba.com).

--------------------------------

> The registered trademark Linux® is used pursuant to a sublicense from the Linux Foundation, the exclusive licensee of Linus Torvalds, owner of the mark on a world­wide basis.
