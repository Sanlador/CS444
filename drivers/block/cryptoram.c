/*
 * An encrypted ram disk driver, adapted from simple block device by the
 * following folks under the following licence:
 *
 * (C) 2003 Eklektix, Inc.
 * (C) 2010 Pat Patterson <pat at superpat dot com>
 * Redistributable under the terms of the GNU GPL.
 *
 *
 * The people who performed this adapation ( (C) 2017  ) are:
 *
 *  Richard Cunard  &  Braxton Cuneo
 *
 * Who also offer this code under the terms of GNU GPL.
 *
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

/* Needed Crypto Headers */
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

MODULE_LICENSE("Dual BSD/GPL");
static char *Version = "1.4";

static int major_num = 0;
module_param(major_num, int, 0);
static int logical_block_size = 512;
module_param(logical_block_size, int, 0);
static int nsectors = 1024; /* How big the drive is */
module_param(nsectors, int, 0);
static char* crypto_key = "Cwm fjord bank glyphs vext quiz.";
module_param(crypto_key, charp, 0);


/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device.
 */
static struct cryptoram_device {
	unsigned long size;
	spinlock_t lock;
	struct crypto_cipher *ECB;
	int blk;
	u8 *data;
	struct gendisk *gd;
} Device;



static void cryptoram_cipher(	struct cryptoram_device *dev,
      				u8 *plain, u8 *code, int len, int write)
{

	int i;
	char* before = kmalloc(sizeof(u8)*(len+1),GFP_KERNEL);
	char* after = kmalloc(sizeof(u8)*(len+1),GFP_KERNEL);
	char* check = kmalloc(sizeof(u8)*(len+1),GFP_KERNEL);
	before[len]=0;
	after[len]=0;
	check[len]=0;
	if (write){
		for(i = 0; i < len; i+=dev->blk){
			crypto_cipher_encrypt_one(	dev->ECB,
			      				&(code[i]),
							&(plain[i]));
			crypto_cipher_decrypt_one(	dev->ECB,
							&(check[i]),
							&(code[i]));
		
		}
		memcpy(before,plain,len);
		memcpy(after,code,len);
		printk(KERN_ERR "\n\nENCRYPTNG DATA:\n\nBEFORE:\n%s",before);
		printk(KERN_ERR "\n\nAFTER:\n%s",after);
		printk(KERN_ERR "\n\nCHECK:\n%s\n",check);
	}
	else{
		for(i = 0; i < len; i+=dev->blk){
			crypto_cipher_decrypt_one(	dev->ECB,
			      				&(plain[i]),
							&(code[i]));
			crypto_cipher_encrypt_one(	dev->ECB,
							&(check[i]),
							&(plain[i]));
		}
		memcpy(before,code,len);
		memcpy(after,plain,len);
		printk(KERN_ERR "\n\nDECRYPTING DATA:\n\nBEFORE:\n%s",before);
		printk("\n\nAFTER:\n%s",after);
		printk("\n\nCHECK:\n%s\n",check);
	}
	kfree(before);
	kfree(after);
	kfree(check);

}


/*
 * Handle an I/O request.
 */
static void cryptoram_transfer(struct cryptoram_device *dev, sector_t sector,
	unsigned long nsect, char *buffer, int write) {
	unsigned long offset = sector * logical_block_size;
	unsigned long nbytes = nsect * logical_block_size;

	if ((offset + nbytes) > dev->size) {
		printk (KERN_NOTICE "cryptoram: Beyond-end write (%ld %ld)\n", 
			offset, nbytes);
		return;
	}
	cryptoram_cipher(dev, buffer, dev->data + offset, nbytes,write);
}

static void cryptoram_request(struct request_queue *q) {
	struct request *req;

	req = blk_fetch_request(q);
	while (req != NULL) {
		// blk_fs_request() was removed in 2.6.36 - many thanks to
		// Christian Paro for the heads up and fix...
		//if (!blk_fs_request(req)) {
		if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
			printk (KERN_NOTICE "Skip non-CMD request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}
		cryptoram_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
				bio_data(req->bio), rq_data_dir(req));
		if ( ! __blk_end_request_cur(req, 0) ) {
			req = blk_fetch_request(q);
		}
	}
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int cryptoram_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
	long size;

	/* We have no real geometry, of course, so make something up. */
	size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;
	return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations cryptoram_ops = {
		.owner  = THIS_MODULE,
		.getgeo = cryptoram_getgeo
};

static int __init cryptoram_init(void) {
	/*
	 * Set up our internal device.
	 */
	Device.size = nsectors * logical_block_size;
	spin_lock_init(&Device.lock);
	Device.data = vmalloc(Device.size);
	if (Device.data == NULL)
		return -ENOMEM;
	
	Device.ECB = NULL;
	Device.ECB = crypto_alloc_cipher(	"aes",
	      					CRYPTO_ALG_TYPE_CIPHER,
	    					CRYPTO_TFM_REQ_MAY_SLEEP);
	if (Device.ECB == NULL){
		printk(KERN_ERR "Unable to load AES transform");
		return -ENOMEM;
	}
	crypto_cipher_setkey(Device.ECB,crypto_key,32);
	Device.blk = crypto_cipher_blocksize(Device.ECB);

	
	/*
	 * Get a request queue.
	 */
	Queue = blk_init_queue(cryptoram_request, &Device.lock);
	if (Queue == NULL)
		goto out;
	blk_queue_logical_block_size(Queue, logical_block_size);
	
	/*
	 * Get registered.
	 */
	major_num = register_blkdev(major_num, "cryptoram");
	if (major_num < 0) {
		printk(KERN_WARNING "cryptoram: unable to get major number\n");
		goto out;
	}
	/*
	 * And the gendisk structure.
	 */
	Device.gd = alloc_disk(16);
	if (!Device.gd)
		goto out_unregister;
	Device.gd->major = major_num;
	Device.gd->first_minor = 0;
	Device.gd->fops = &cryptoram_ops;
	Device.gd->private_data = &Device;
	strcpy(Device.gd->disk_name, "cryptoram0");
	set_capacity(Device.gd, nsectors);
	Device.gd->queue = Queue;
	add_disk(Device.gd);

	return 0;

out_unregister:
	unregister_blkdev(major_num, "cryptoram");
out:
	vfree(Device.data);
	return -ENOMEM;
}

static void __exit cryptoram_exit(void)
{
	del_gendisk(Device.gd);
	put_disk(Device.gd);
	unregister_blkdev(major_num, "cryptoram");
	blk_cleanup_queue(Queue);
	crypto_free_cipher(Device.ECB);
	vfree(Device.data);
}

module_init(cryptoram_init);
module_exit(cryptoram_exit);

