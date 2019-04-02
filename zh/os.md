---
title: Alibaba Cloud Linux 2
description: 阿里云上原生的免费开源操作系统发行版
---

Alibaba Cloud Linux 2 操作系统简介
=================================

+ [English Version](../os.md)

目录
----
1. [Alibaba Cloud Linux 2 是什么](#1-alibaba-cloud-linux-2-是什么)
2. [如何使用 Alibaba Cloud Linux 2](#2-如何使用-alibaba-cloud-linux-2)
3. [获取源码](#3-获取源码)
4. [获取帮助](#4-获取帮助)

-------------------------

## 1. Alibaba Cloud Linux 2 是什么

Alibaba Cloud Linux 操作系统(原名 _Aliyun Linux_)是一款开源且免费的 Linux 操作系统发行版，旨在为阿里云 ECS 客户提供丰富功能，高性能且稳定的操作系统服务。

Alibaba Cloud Linux 2 是 Alibaba Cloud Linux 的下一代版本，其开发团队是阿里巴巴操作系统团队，前身是淘宝内核组。九年来，团队成员大多是活跃在内核社区的开发者，积累了深厚的操作系统和内核开发底蕴。

## 2. 如何使用 Alibaba Cloud Linux 2

当前我们随阿里云 ECS 实例免费提供 Alibaba Cloud Linux 2 操作系统镜像。如需使用，可以通过以下链接购买 ECS 实例：[中文站](https://ecs-buy.aliyun.com/), [eng](https://ecs-buy-intl.aliyun.com/).

## 3. 获取源码

在 Alibaba Cloud Linux 2 操作系统中，您可以通过 `yumdownloader` 工具下载到源码（请确保您已经安装了 `yum-utils` RPM 包）：

```bash
sudo yum install -y yum-utils
sudo yumdownloader --source <包名>
```

此外，您还可以从 [Alibaba Cloud Linux Kernel](https://github.com/alibaba/cloud-kernel) 的 Github 项目中获取阿里云 Linux 内核(ALK)源码。

## 4. 获取帮助

在使用 Alibaba Cloud Linux 操作系统的过程中如需获取帮助，您可以尝试下列途径：

+ 如果您是阿里云 ECS 用户，可以提交[工单](https://selfservice.console.aliyun.com/ticket/createIndex)；
+ 可以加入[邮件列表](MAILLIST.md)参与讨论；
+ 可以加入[开发者论坛](https://bbs.aliyun.com/thread/450.html)参与讨论；
+ 可以加入钉钉群：`Alibaba Cloud Linux OS 开发者&用户群`，群号：`23149462`;
+ 或者可以给我们发邮件：[alicloud-linux-os@service.alibaba.com](mailto:alicloud-linux-os@service.alibaba.com).

--------------------------------

> The registered trademark Linux® is used pursuant to a sublicense from the Linux Foundation, the exclusive licensee of Linus Torvalds, owner of the mark on a world­wide basis.
