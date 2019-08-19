Alibaba Cloud Kernel
====================

+ [中文版](zh/README.md)

Table of Contents
-----------------
1. [What is Alibaba Cloud Kernel](#1-what-is-alibaba-cloud-kernel)
2. [Getting Started](#2-getting-started)
   1. [Run with pre-built RPMs (recommended)](#21-run-with-pre-built-rpms-recommended)
   2. [Compile from source](#22-compile-from-source)
3. [Contributing](#3-contributing)
4. [Credits](#4-credits)
5. [License](#5-license)
6. [Contact Us](#6-contact-us)

---------------------------------


## 1. What is Alibaba Cloud Kernel

Alibaba Cloud Kernel(a.k.a. the "Cloud Kernel"), a customized and optimized version of Linux kernel, is originated by Alibaba Operating System Team (formerly known as Taobao Kernel Team). Cloud Kernel is installed as the default kernel in Alibaba Cloud Linux OS version 2 (or Aliyun Linux 2), which is running on Alibaba Cloud Elastic Compute Service (ECS) product. In Cloud Kernel, several features and enhancements adapted to specific Alibaba Cloud infrastructre and products have been made to help Alibaba Cloud customers to achieve better user experiences.

Like many other kernels, Cloud Kernel should work with almost all commonly-used Linux distributions, however, we highly recommend you run it in Alibaba Cloud Linux OS with Alibaba Cloud ECS instances to get best functionality, performance and stability.

To get more information about Alibaba Cloud Linux OS, please refer to [this](os.md) link.

## 2. Getting Started

To use Cloud Kernel, you may want either to run a pre-built version or to compile it from source codes. Note that the default kernel configuration file is a customized version for Alibaba Cloud ECS instances, you might need to enable specific drivers and re-compile the kernel if you want to run it on non-ECS platforms.

### 2.1 Run with pre-built RPMs (recommended)

Installing from YUM source repo is the most recommended way:

+ Step 1: Create a new YUM repo file:

```shell
sudo vim /etc/yum.repos.d/alinux-2.1903-plus.repo
```

+ Step 2: Fill repository information into the repo file:

```shell
[plus]
name=Alibaba Cloud Linux 2.1903 Plus Software Collections
baseurl=http://mirrors.aliyun.com/alinux/2.1903/plus/x86_64/
enabled=1
gpgcheck=1
gpgkey=http://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
```

+ Step 3: Install the kernel:

```shell
sudo yum install -y kernel kernel-devel kernel-headers
```

+ Step 4: Reboot system and enjoy Cloud Kernel.

### 2.2 Compile from source

+ Step 1: Fetch kernel source:
  + Download from [Releases](https://github.com/alibaba/cloud-kernel/releases) page for a stable release and extract the source;
  + Or clone from the project repo: `git clone git@github.com:alibaba/cloud-kernel.git`.

+ Step 2: Fetch a [default kernel config](config-4.19.y-x86_64) from `master` branch and rename it to `.config`, then copy it to the top of kernel source directory;

+ Step 3: Compile and install kernel via the following commands:

```shell
make oldconfig
make -jN # N normally refers to the CPU core numbers on the system
make modules -jN
sudo make modules_install
sudo make install
```

+ Step 4: Reboot system and enjoy Cloud Kernel.

## 3. Contributing

There are different ways to contribute to Cloud Kernel project, please read [CONTRIBUTING](CONTRIBUTING.md) file to get more details.

## 4. Credits

A full list of contributors from teams and individuals inside and out of Alibaba Group could be found in [CREDITS](CREDITS.md) file. And special thanks would be given to:
+ [CentOS project](https://www.centos.org/);
+ [Clear Linux project](https://clearlinux.org/);
+ [Intel 0-Day (LKP) project](https://01.org/lkp);
+ [Kata Containers project](https://katacontainers.io/);
+ [Linux kernel project](https://www.kernel.org/).

## 5. License

We use the same license as the upstream does, so please refer to the [COPYING](COPYING) file.

## 6. Contact Us

+ Join the [mailing list discussions](MAILLIST.md);
+ Join the [forum discussions](https://bbs.aliyun.com/thread/450.html);
+ Send us an E-mail to [alicloud-linux-os@service.alibaba.com](mailto:alicloud-linux-os@service.alibaba.com) is always a good idea.

--------------------------------

> The registered trademark Linux® is used pursuant to a sublicense from the Linux Foundation, the exclusive licensee of Linus Torvalds, owner of the mark on a world­wide basis.
