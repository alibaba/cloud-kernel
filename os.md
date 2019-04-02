---
title: Alibaba Cloud Linux OS
description: An open-source Linux distribution powered by Alibaba Cloud
---

Brief Introduction to Alibaba Cloud Linux OS
============================================

+ [中文版](zh/os.md)

Table of Contents
-----------------
1. [What is Alibaba Cloud Linux OS](#1-what-is-alibaba-cloud-linux-os)
2. [How to use](#2-how-to-use)
3. [Getting source](#3-getting-source)
4. [Getting helps](#4-getting-helps)

-------------------------

## 1. What is Alibaba Cloud Linux OS

Alibaba Cloud Linux (a.k.a. Aliyun Linux) OS is an open-source Linux distribution originated by Alibaba Operating System team, aiming to deliver OS services with various functionality, high performance and stability to Alibaba Cloud Elastic Compute Service (ECS) customers.

Current released version is Alibaba Cloud Linux OS version 2, or known as 'Aliyun Linux 2'.

## 2. How to use

Simply buy an ECS instance and get started: [chs](https://ecs-buy.aliyun.com/), [eng](https://ecs-buy-intl.aliyun.com/).

## 3. Getting source

When running with an Alibaba Cloud Linux 2 OS, you should be able to fetch source RPMs via `yumdownloader` tool (make sure you have `yum-utils` package installed first):

```bash
sudo yum install -y yum-utils
sudo yumdownloader --source <source package>
```

Meanwhile, you are free to fetch kernel source from [Alibaba Cloud Linux Kernel](https://github.com/alibaba/cloud-kernel) project.

## 4. Getting Helps

To get helps when using Alibaba Cloud Linux OS, you can

+ File a [ticket](https://selfservice.console.aliyun.com/ticket/createIndex) if you are an Alibaba Cloud ECS customer;
+ Join the [mailing list discussions](MAILLIST.md);
+ Join the [forum discussions](https://bbs.aliyun.com/thread/450.html);
+ Send us an E-mail to [alicloud-linux-os@service.alibaba.com](mailto:alicloud-linux-os@service.alibaba.com).

------------------------

> The registered trademark Linux® is used pursuant to a sublicense from the Linux Foundation, the exclusive licensee of Linus Torvalds, owner of the mark on a world­wide basis.
