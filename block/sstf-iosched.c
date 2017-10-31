/*
 * elevator clook
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>

struct clook_data {
	struct list_head queue;
	//add pointer to maintain indexing in place of queue
	struct list_head index;
};

static void clook_merged_requests(struct request_queue *q, struct request *rq,
				 struct request *next)
{
	list_del_init(&next->queuelist);
}

static int clook_dispatch(struct request_queue *q, int force)
{
	struct clook_data *nd = q->elevator->elevator_data;

	if (!list_empty(&nd->queue)) {
		struct request *rq;
		//changed queue to index
		rq = list_entry(nd->index.next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		elv_dispatch_sort(q, rq);
		printk( KERN_ALERT "Disk head position: %i\n",
		        (int) blk_rq_pos(rq));
		if(rq_data_dir(rq) == READ)
			printk( KERN_ALERT "Reading\n");
		else
			printk( KERN_ALERT "Writing\n");
		return 1;
	}
	return 0;
}

static void clook_add_request(struct request_queue *q, struct request *rq)
{
	struct clook_data *nd = q->elevator->elevator_data;
	struct request *temp_req = list_entry(nd->queue.next, struct request, queuelist);
	int disk_head_pos;
	if(list_empty(&(nd->queue))){
		//Adds to empty queue and returns
		list_add(rq, temp_req->queuelist.next);
		disk_head_pos = blk_rq_pos(rq);
		if (rq_data_dir(rq) == READ){
			printk("Writing to disk position %i\n", disk_head_pos);
		}
		else {
			printk("Reading from disk positiob %i\n", disk_head_pos);
		}
	}	

	while (blk_rq_pos(rq) > blk_rq_pos(temp_req)){
		//use list_entry to iterate through queue
		temp_req = list_entry(temp_req->queuelist.next, struct request, queuelist);	
	}
	
	//Unless list is empty, function will reach here and insert into queue
	list_add(rq, temp_req->queuelist.next);
	disk_head_pos = blk_rq_pos(rq);

	if (rq_data_dir(rq) == READ){
		printk("Writing to disk position %i\n", disk_head_pos);
	}
	else {
		printk("Reading from disk positiob %i\n", disk_head_pos);
	}
}

static struct request *
clook_former_request(struct request_queue *q, struct request *rq)
{
	struct clook_data *nd = q->elevator->elevator_data;

	//use index in place of queue
	if (rq->queuelist.prev == &nd->index)
		return NULL;
	return list_entry(rq->queuelist.prev, struct request, queuelist);
}

static struct request *
clook_latter_request(struct request_queue *q, struct request *rq)
{
	struct clook_data *nd = q->elevator->elevator_data;

	//use index in place of queue
	if (rq->queuelist.next == &nd->index)
		return NULL;
	return list_entry(rq->queuelist.next, struct request, queuelist);
}

static int clook_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct clook_data *nd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	nd = kmalloc_node(sizeof(*nd), GFP_KERNEL, q->node);
	if (!nd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = nd;

	INIT_LIST_HEAD(&nd->queue);
	nd->index = nd->queue;

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);
	return 0;
}

static void clook_exit_queue(struct elevator_queue *e)
{
	struct clook_data *nd = e->elevator_data;

	BUG_ON(!list_empty(&nd->queue));
	kfree(nd);
}

static struct elevator_type elevator_clook = {
	.ops = {
		.elevator_merge_req_fn		= clook_merged_requests,
		.elevator_dispatch_fn		= clook_dispatch,
		.elevator_add_req_fn		= clook_add_request,
		.elevator_former_req_fn		= clook_former_request,
		.elevator_latter_req_fn		= clook_latter_request,
		.elevator_init_fn		= clook_init_queue,
		.elevator_exit_fn		= clook_exit_queue,
	},
	.elevator_name = "clook",
	.elevator_owner = THIS_MODULE,
};

static int __init clook_init(void)
{
	return elv_register(&elevator_clook);
}

static void __exit clook_exit(void)
{
	elv_unregister(&elevator_clook);
}

module_init(clook_init);
module_exit(clook_exit);

MODULE_AUTHOR("Team 2: Richard Cunard & Braxton Cuneo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Look IO scheduler");
