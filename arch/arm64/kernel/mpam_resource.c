#include <linux/io.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/kthread.h>
#include <linux/resctrlfs.h>

#include <asm/mpam_resource.h>
#include <asm/mpam.h>

