#include <linux/virtio.h>
#include <linux/virtio_tpm.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/oom.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/tpm.h>
#include "tpm.h"
#include "tpm_crb.h"

#include <linux/device.h>
#include <linux/acpi.h>
#include <linux/kernel.h>


struct virtio_tpm {
    struct virtio_device *vdev;
    struct virtqueue *data_vq;

    struct work_struct print_val_work;
    bool stop_update;
    atomic_t stop_once;

    /* Waiting for host to ack the pages we released. */
    wait_queue_head_t acked;

    __virtio32 num[256];
};

static struct virtio_device_id id_table[] = {
    { VIRTIO_ID_TPM, VIRTIO_DEV_ANY_ID },
    { 0 },
};

static struct virtio_tpm *vb_dev;

static void tpm_ack(struct virtqueue *vq)
{
    struct virtio_tpm *vb = vq->vdev->priv;
    printk("virttpm get ack\n");
    unsigned int len;
    virtqueue_get_buf(vq, &len);
}

static int init_vqs(struct virtio_tpm *vb)
{
    struct virtqueue *vqs[1];
    vq_callback_t *callbacks[] = { tpm_ack };
    static const char * const names[] = { "data"};
    int err, nvqs;

    nvqs = 1 ;             //virtio_has_feature(vb->vdev, VIRTIO_tpm_F_CAN_PRINT) ? 1 : 0;
    err = virtio_find_vqs(vb->vdev, nvqs, vqs, callbacks, names, NULL);
    if (err)
        return err;

    vb->data_vq = vqs[0];

    printk("***********virtio init_vqs\n");

    return 0;
}


static void remove_common(struct virtio_tpm *vb)
{
    /* Now we reset the device so we can clean up the queues. */
    vb->vdev->config->reset(vb->vdev);

    vb->vdev->config->del_vqs(vb->vdev);
}

static void virttpm_remove(struct virtio_device *vdev)
{
    struct virtio_tpm *vb = vdev->priv;

    remove_common(vb);
    cancel_work_sync(&vb->print_val_work);
    kfree(vb);
    vb_dev = NULL;
}

static int virttpm_validate(struct virtio_device *vdev)
{
    return 0;
}

static void print_val_func(struct work_struct *work)
{
    struct virtio_tpm *vb;
    struct scatterlist sg;

    printk("***********virtio print_val_func\n");

    vb = container_of(work, struct virtio_tpm, print_val_work);
    printk("virttpm get config change\n");

    struct virtqueue *vq = vb->data_vq;
    vb->num[0]++;
    sg_init_one(&sg, &vb->num[0], sizeof(vb->num[0]));

    /* We should always be able to add one buffer to an empty queue. */
    virtqueue_add_outbuf(vq, &sg, 1, vb, GFP_KERNEL);
    virtqueue_kick(vq);
}

static int test_send(void)
{
    struct scatterlist sg[1];
    int err;

    printk("***********virtio virtio_send\n");
    struct virtqueue *vq = vb_dev->data_vq;

    vb_dev->num[0]++;
    sg_init_one(sg, &vb_dev->num[0], sizeof(vb_dev->num[0]));

    printk("***********virtio virtio_send num\n");

    if(!vq){
        printk("*************vq is NULL\n");
    }else{
        printk("*************vq is ok\n");
    }

    if(!vb_dev){
        printk("*************vb is NULL\n");
    }else{
        printk("*************vb is ok\n");
    }

    if(!sg){
        printk("*************sg is NULL\n");
    }else{
        printk("*************sg is ok\n");
    }

    err = virtqueue_add_inbuf(vq, sg, 1, vb_dev, GFP_KERNEL);

    if(err){
        printk("************virtqueue_add_inbuf error :%d\n",err);
    }else{
        printk("************virtqueue_add_inbuf ok : %d\n",err);
    }

    printk("***********virtio virtio_send add_inbuf\n");

    if(virtqueue_kick(vq)){
        printk("*************virtqueue_kick error\n");
    }else{
        printk("*************virtqueue_kick ok\n");
    }

    printk("***********virtio virtio_send kick\n");
    return 0;

}

static int virtio_tpm_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	struct scatterlist sg[1];
    struct virtqueue *vq = vb_dev->data_vq;
	int err;

    printk("**************virtio_tpm_send begin\n");

    if (len > TPM_BUFSIZE) {
        printk("*********virtio_tpm_send len :%zd .len > TPM_BUFSIZE\n",len);
		//dev_err(&chip->dev, "invalid command count value %zd %d\n",len, priv->cmd_size);
		return -E2BIG;
	}

	sg_init_one(sg, buf, len);
	
    printk("***************virtio_tpm_send buf :%s\n",buf);
    if(!vq){
        printk("**************virtio_tpm_send vq NULL\n");
    }
	err = virtqueue_add_inbuf(vq, sg, 1, vb_dev, GFP_KERNEL);
    printk("**************virtio_tpm_send : %d\n", err);

	virtqueue_kick(vq);

    printk("**************virtio_tpm_send end\n");

	return 0;
}


static int virtio_tpm_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{

	//struct virtio_tpm *priv = dev_get_drvdata(&chip->dev);
	int len;
	// int ret;

    printk("**************virtio_tpm_recv begin\n");

	buf = (u8 *) virtqueue_get_buf(vb_dev->data_vq, &len);
    printk("***************virtio_tpm_recv buf :%s\n",buf);

	dev_dbg(&chip->dev, "%s %u bytes\n", __func__, len);

    //send to tpm
    struct crb_priv *priv = dev_get_drvdata(&chip->dev);
	unsigned int expected;

	/* A sanity check that the upper layer wants to get at least the header
	 * as that is the minimum size for any TPM response.
	 */
	if (count < TPM_HEADER_SIZE)
		return -EIO;

	/* If this bit is set, according to the spec, the TPM is in
	 * unrecoverable condition.
	 */
	if (ioread32(&priv->regs_t->ctrl_sts) & CRB_CTRL_STS_ERROR)
		return -EIO;

	/* Read the first 8 bytes in order to get the length of the response.
	 * We read exactly a quad word in order to make sure that the remaining
	 * reads will be aligned.
	 */
	memcpy_fromio(buf, priv->rsp, 8);

	expected = be32_to_cpup((__be32 *)&buf[2]);
	if (expected > count || expected < TPM_HEADER_SIZE)
		return -EIO;

	memcpy_fromio(&buf[8], &priv->rsp[8], expected - 8);

    printk("**************virtio_tpm_recv end\n");

	return expected;
}


static void virttpm_changed(struct virtio_device *vdev)
{
    struct virtio_tpm *vb = vdev->priv;
    printk("virttpm virttpm_changed\n");
    if (!vb->stop_update) {
        //atomic_set(&vb->stop_once, 0);
        queue_work(system_freezable_wq, &vb->print_val_work);
    }
}

enum crb_status {
	CRB_DRV_STS_COMPLETE	= BIT(0),
};

static const struct tpm_class_ops tpm_crb_new = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.status = crb_status,
	.recv = virtio_tpm_recv,
	.send = virtio_tpm_send,
	.cancel = crb_cancel,
	.req_canceled = crb_req_canceled,
	.go_idle  = crb_go_idle,
	.cmd_ready = crb_cmd_ready,
	.request_locality = crb_request_locality,
	.relinquish_locality = crb_relinquish_locality,
	.req_complete_mask = CRB_DRV_STS_COMPLETE,
	.req_complete_val = CRB_DRV_STS_COMPLETE,
};

// 回调函数，用于在遍历过程中处理每个设备
static acpi_status acpi_device_callback(acpi_handle handle, u32 level, void *context, void **retval) {
    struct acpi_device *device = NULL;

    printk("***************acpi_device_callback\n");
    // 获取acpi_device
    if (acpi_bus_get_device(handle, &device) == AE_OK) {
        printk("***************acpi_bus_get_device\n");
        pr_info("ACPI Device found: %s\n", acpi_device_hid(device));
        if (!strcmp(acpi_device_hid(device), (char *)context)) {
            pr_info("Matched device: %s\n", acpi_device_hid(device));

            struct device *dev = &device->dev;
	        struct tpm_chip *chip = dev_get_drvdata(dev);

            chip->ops = &tpm_crb_new;
            printk("************change crb send");

            *retval = device;
            return AE_CTRL_TERMINATE;  // 找到设备，停止遍历
        }
    }
    return AE_OK;
}

// 查找指定ACPI ID的设备
struct acpi_device *find_acpi_device_by_id(const char *acpi_id) {
    struct acpi_device *device = NULL;

    printk("***************find_acpi_device_by_id\n");
    // 遍历ACPI namespace以找到匹配的设备
    acpi_walk_namespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT, ACPI_UINT32_MAX,
                        acpi_device_callback, NULL, (void *)acpi_id, (void **)&device);

    if (device) {
        pr_info("Found ACPI device with ID: %s\n", acpi_id);
    } else {
        pr_err("No ACPI device found with ID: %s\n", acpi_id);
    }

    return device;
}

static int virttpm_probe(struct virtio_device *vdev)
{
    struct virtio_tpm *vb;
    int err;

    printk("******create virttpm\n");
    if (!vdev->config->get) {
        return -EINVAL;
    }

    vdev->priv = vb = kmalloc(sizeof(*vb), GFP_KERNEL);
    if (!vb) {
        err = -ENOMEM;
        goto out;
    }
    vb->num[0] = 0;
    vb->vdev = vdev;
    INIT_WORK(&vb->print_val_work, print_val_func);

    vb->stop_update = false;

    init_waitqueue_head(&vb->acked);
    err = init_vqs(vb);
    if (err)
        goto out_free_vb;

    virtio_device_ready(vdev);

    atomic_set(&vb->stop_once, 0);
    vb_dev = vb;

    find_acpi_device_by_id("MSFT0101");
    //test_send();

    return 0;

out_free_vb:
    kfree(vb);
out:
    return err;
}

static unsigned int features[] = {

};

static struct virtio_driver virtio_tpm_driver = {
    .feature_table = features,
    .feature_table_size = ARRAY_SIZE(features),
    .driver.name =  KBUILD_MODNAME,
    .driver.owner = THIS_MODULE,
    .id_table = id_table,
    .validate = virttpm_validate,
    .probe =    virttpm_probe,
    .remove =   virttpm_remove,
    .config_changed = virttpm_changed,
};

static int __init virtio_tpm_init(void) {
    printk(KERN_INFO "***********virtio_tpm module loaded\n");
    return 0;
}
static void __exit virtio_tpm_exit(void) {
    printk(KERN_INFO "virtio_tpm module unloaded\n");
}

module_init(virtio_tpm_init);
module_exit(virtio_tpm_exit);
module_virtio_driver(virtio_tpm_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio tpm driver");
MODULE_LICENSE("GPL");