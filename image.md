Alibaba Cloud Linux 2 On-Premise Image
======================================

[ 中文版 ](https://github.com/alibaba/cloud-kernel/wiki/Aliyun-Linux-2-On-Premise-Image)

We provide Alibaba Cloud Linux 2 virtual machine images for on-premises development and testing. To use the VM image, you need to do the following steps:

+ Step 1: Download the Alibaba Cloud Linux 2 VM Image;
+ Step 2: Prepare the seed.img Boot Image;
+ Step 3: Boot the New VM.

## Step 1: Download the Alibaba Cloud Linux 2 VM Image

Currently the image is available for QEMU/KVM virtualization platform only, the image format is `qcow2`, and `virtio` drivers are used in guest operating system.

| File | SHA256SUM |
|------|-----------|
| [seed.img](https://alinux2.oss-cn-hangzhou.aliyuncs.com/seed.img) | 7fd5c245c2daef9454b98b251215f5f667d415d5759389f12d0de77d15225586 |
| [aliyun_2_1903_64_20G_alibase_20190619.onprem.vhd](https://alinux2.oss-cn-hangzhou.aliyuncs.com/aliyun_2_1903_64_20G_alibase_20190619.onprem.vhd) | 426400dfb706770a090808de5ffee0e6f725f1d9dab525b88365a70484788ddf |
| [aliyun_2_1903_64_20G_alibase_20190619.onprem.qcow2](https://alinux2.oss-cn-hangzhou.aliyuncs.com/aliyun_2_1903_64_20G_alibase_20190619.onprem.qcow2) | 1e0d7620fc34f928666ce945f2da9583b126a40638b20b79c7c17142aefcb638 |

## Step 2: Prepare the seed.img Boot Image

To boot your new VM and get the configurations initialized, you should prepare a `seed.img` boot image, which will be used by [cloud-init](https://cloudinit.readthedocs.io/en/latest/), to set up network configrations, host name, YUM source, etc. It is highly recommended to read cloud-init documentations before getting started.

We use NoCloud data source in cloud-init, which requires a virtual disk drvier attached to VM, including two configuration files: `meta-data` and `user-data`.

+ Create a plain-text file named `meta-data`, fill the contents as follows:

```yaml
#cloud-config
#vim:syntax=yaml

local-hostname: alinux-host
# FIXME: does not work for systemd-networkd
#network-interfaces: |
#  iface eth0 inet static
#  address 192.168.122.68
#  network 192.168.122.0
#  netmask 255.255.255.0
#  broadcast 192.168.122.255
#  gateway 192.168.122.1
```

+ Create a plain-text file named `user-data`, fill the contents as follows:

```yaml
#cloud-config
#vim:syntax=yaml

# add a new account alinux, allow sudo priv
users:
  - default
  - name: alinux
    sudo: ['ALL=(ALL)   ALL']
    plain_text_passwd: aliyun
    lock_passwd: false

# add yum source
yum_repos:
    base:
        baseurl: https://mirrors.aliyun.com/alinux/$releasever/os/$basearch/
        enabled: true
        gpgcheck: true
        gpgkey: https://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
        name: Aliyun Linux - $releasever - Base - mirrors.aliyun.com
    updates:
        baseurl: https://mirrors.aliyun.com/alinux/$releasever/updates/$basearch/
        enabled: true
        gpgcheck: true
        gpgkey: https://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
        name: Aliyun Linux - $releasever - Updates - mirrors.aliyun.com
    extras:
        baseurl: https://mirrors.aliyun.com/alinux/$releasever/extras/$basearch/
        enabled: true
        gpgcheck: true
        gpgkey: https://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
        name: Aliyun Linux - $releasever - Extras - mirrors.aliyun.com
    plus:
        baseurl: https://mirrors.aliyun.com/alinux/$releasever/plus/$basearch/
        enabled: true
        gpgcheck: true
        gpgkey: https://mirrors.aliyun.com/alinux/RPM-GPG-KEY-ALIYUN
        name: Aliyun Linux - $releasever - Plus - mirrors.aliyun.com

# FIXME: This is a workaround for network settings since the steps in
#        meta-data fail to work. Blame cloud-init or systemd-networkd :)
write_files:
  - path: /etc/systemd/network/20-eth0.network
    permissions: 0644
    owner: root
    content: |
      [Match]
      Name=eth0

      [Network]
      Address=192.168.122.68/24
      Gateway=192.168.122.1

# FIXME: this is also a workaround for network settings.
runcmd:
  - ifdown eth0
  - systemctl restart systemd-networkd
```

> You should at least adjust the network sections to match the real network configurations you have.

+ Create the `seed.img` with the tool `cloud-localds` provided in `cloud-utils` package:

Install `cloud-utils` package by:

```bash
yum install -y cloud-utils
```

Then execute the following command at the same directory level as the files `meta-data` and `user-data`:

```bash
cloud-localds seed.img user-data meta-data
```

to produce a `seed.img`. Note this image only includes configuration information required to boot the VM by cloud-init, it does not include the Alibaba Cloud Linux 2 operating system files.

You could also download a `seed.img` from the table provided in Step 1. Please avoid using it if network access is mandatory but your network configuration is not `192.168.122.0/24`.

## Step 3: Boot the New VM.

You should attach `seed.img` to a KVM virtual machine running with Alibaba Cloud Linux 2 on-premise image.

- If you created the VM with GUI, like virt-manager, please add a new virtual disk driver with `seed.img`, then boot the VM;

- If you created it with a Libvirt XML, you need to add the following section to the XML file:

```xml
        <disk type='file' device='disk'>
            <driver name='qemu' type='raw'/>
            <source file='/path/to/your/seed.img'/> <!-- absolute path of seed.img -->
            <target dev='vdb' bus='virtio'/>
        </disk>
```
- If you run the VM directly with a qemu-kvm command line, you should append the following options:

```bash
-drive file=/path/to/your/seed.img,if=none,id=drive-virtio-disk1,format=raw,cache=none,aio=native \
-device virtio-blk-pci,scsi=off,x-data-plane=on,config-wce=off,bus=pci.0,addr=0x6,drive=drive-virtio-disk1,id=virtio-disk1
```
