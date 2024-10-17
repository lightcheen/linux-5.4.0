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


struct virtio_tpm {
    struct virtio_device *vdev;
    struct virtqueue *send_vq;

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
    static const char * const names[] = { "print"};
    int err, nvqs;

    nvqs = 0 ;             //virtio_has_feature(vb->vdev, VIRTIO_tpm_F_CAN_PRINT) ? 1 : 0;
    err = virtio_find_vqs(vb->vdev, nvqs, vqs, callbacks, names, NULL);
    if (err)
        return err;

    vb->send_vq = vqs[0];

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

    struct virtqueue *vq = vb->send_vq;
    vb->num[0]++;
    sg_init_one(&sg, &vb->num[0], sizeof(vb->num[0]));

    /* We should always be able to add one buffer to an empty queue. */
    virtqueue_add_outbuf(vq, &sg, 1, vb, GFP_KERNEL);
    virtqueue_kick(vq);
}

static void tpm_send(struct virtio_tpm *vb)
{
    struct scatterlist sg[1];
    int err;

    printk("***********virtio tpm_send\n");
    struct virtqueue *vq = vb->send_vq;

    vb->num[0]++;
    sg_init_one(sg, &vb->num[0], sizeof(vb->num[0]));

    printk("***********virtio tpm_send num\n");

    if(!vq){
        printk("*************vq is NULL\n");
    }else{
        printk("*************vq is ok\n");
    }

    if(!vb){
        printk("*************vb is NULL\n");
    }else{
        printk("*************vb is ok\n");
    }

    if(!sg){
        printk("*************sg is NULL\n");
    }else{
        printk("*************sg is ok\n");
    }

    err = virtqueue_add_inbuf(vq, sg, 1, vb, GFP_KERNEL);

    if(err){
        printk("************virtqueue_add_inbuf error :%d\n",err);
    }else{
        printk("************virtqueue_add_inbuf ok : %d\n",err);
    }

    printk("***********virtio tpm_send add_inbuf\n");

    if(virtqueue_kick(vq)){
        printk("*************virtqueue_kick error\n");
    }else{
        printk("*************virtqueue_kick ok\n");
    }

    printk("***********virtio tpm_send kick\n");

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

    tpm_send(vb);

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