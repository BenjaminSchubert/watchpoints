#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "watchpoints.h"
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>


MODULE_AUTHOR("Benjamin Schubert <benjamin.schubert@epfl.ch>");
MODULE_DESCRIPTION
    ("Set watchpoints from proc without going through ptrace");
MODULE_LICENSE("GPL");


/* on x86_64 there are only 4 watchpoints */
#define WATCHPOINTS_MAX 4


struct proc_dir_entry *proc_watchpoints;

/* Change_list object, to keep track of any change in the tracked data */
struct tracked_changes_list {
	/* new value of the data */
	u8 *data;
	/* size of the data chunk */
	size_t data_size;
	/* list to which the data belongs */
	struct list_head list;
};

struct tracked_pointer_list {
	void *ptr;
	size_t size;
	struct proc_dir_entry *entry;
	struct list_head list;
	struct tracked_changes_list *changes;
};

struct tracked_pid_list {
	pid_t pid;
	struct proc_dir_entry *entry;
	struct list_head list;
	struct tracked_pointer_list *pointers;
};

	
struct tracked_pid_list tracked_data;



static void watchpoint_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs);
static long watchpoints_ioctl(struct file *file, unsigned int cmd,
			      long unsigned ptr_message);


static int __init watchpoint_init(void);
static void __exit watchpoint_exit(void);


const struct file_operations ctrl_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.unlocked_ioctl = watchpoints_ioctl,
	.open = NULL,
	.release = NULL,
};

static struct miscdevice watchpoints_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "watchpoints",
	.fops = &ctrl_fops
};


const struct file_operations proc_fops = {
	.read = NULL,
	.write = NULL
};

module_init(watchpoint_init);
module_exit(watchpoint_exit);


struct tracked_pointer_list *get_pointer_list_for_pid(u64 pid) {
	struct list_head *pos;
	
	list_for_each(pos, &tracked_data.list) {
		if(list_entry(pos, struct tracked_pid_list, list)->pid
			== pid) {
			printk(KERN_INFO "PID IS %llu\n", pid);
			return list_entry(pos, struct tracked_pid_list, list)->pointers;	
		}
	}
	return NULL;
}

struct tracked_pointer_list *get_pointer_from_pointer_list(struct tracked_pointer_list *pointer_list, long ptr) {
	struct tracked_pointer_list *pointer;
	
	for(i = 1; i < 1; i++) { printk("I GOT IT\n"); }
	if(&pointer_list->list == pointer_list->list.next) printk("THIS IS THE SAME\n");
	list_for_each_entry(pointer, &pointer_list->list, list) {
		printk("AM I EMPTY ?\n");
		/*pointer = list_entry(pos, struct tracked_pointer_list, list);
		printk("THE POINTER IS %p\n", pointer->ptr);
		if((long) list_entry(pos, struct tracked_pointer_list, list)->ptr == ptr) {
			return list_entry(pos, struct tracked_pointer_list, list);
		}*/
	}
	
	if(list_is_singular(&pointer_list->list)) {
		printk("I AM ALONE\n");
	}
	printk("THERE IS NOTHING HERE\n");
	return NULL;
}

static void watchpoint_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
	struct tracked_pointer_list *pointer_list;
	
	struct tracked_pointer_list *pointer;
	/*struct tracked_changes_list *new_change;
	*/
	printk("The REAL PTR IS %llx\n", bp->attr.bp_addr);
	pointer_list = get_pointer_list_for_pid(bp->ctx->task->pid);
	pointer = get_pointer_from_pointer_list(pointer_list, bp->attr.bp_addr);
	
	if(!pointer) {
		printk("ABORT ABORT\n");
		return;
	}
	printk("The pointer is %p\n", pointer->ptr);

	
/*	new_change = kmalloc(sizeof(*new_change), 0);
	new_change->data = kmalloc(pointer->size, 0);
	printk(KERN_INFO "Pointer is %ld, size is %ld\n", pointer->ptr, pointer->size);
	return;
	copy_from_user(new_change->data, (void *) pointer->ptr, pointer->size);
	printk(KERN_INFO "WE ARE THERE\n");
	printk(KERN_DEBUG
		"Process %d at position %ld, new value: %s\n",
		bp->ctx->task->pid, pointer->ptr, new_change->data);
	
*/	
}


static struct perf_event *initialize_breakpoint(struct watchpoint_message data, pid_t pid) {
	struct perf_event *perf_watchpoint;
	struct task_struct *tsk;
	struct perf_event_attr attr;
	
	/* Initialize breakpoint */
	hw_breakpoint_init(&attr);
	attr.bp_addr = (u64) data.data_ptr;
	attr.bp_len = HW_BREAKPOINT_LEN_4;
	attr.bp_type = HW_BREAKPOINT_W;

	tsk = pid_task(find_vpid(pid), PIDTYPE_PID);

	perf_watchpoint =
	    register_user_hw_breakpoint(&attr, watchpoint_handler,
					NULL, tsk);
					
	return perf_watchpoint;
}


static void add_ptr_entry_to_pid(struct tracked_pid_list *tracked_pid, struct watchpoint_message ptr) {
	struct list_head *pos;
	int ptr_entry_created = 0;

	if(tracked_pid->pointers) {
		list_for_each(pos, &tracked_pid->pointers->list) {
			struct tracked_pointer_list *ptr_entry;
			ptr_entry = list_entry(pos, struct tracked_pointer_list, list);
			if(ptr_entry->ptr == ptr.data_ptr) {
				ptr_entry_created = 1;
				break;
			}
		}
	}

	if(!ptr_entry_created) {
		struct proc_dir_entry *proc_ptr;
		struct tracked_changes_list *changes;
		struct tracked_pointer_list *ptr_entry;
		char ptr_value[2*sizeof(long) + 1];
		
		sprintf(ptr_value, "%p", ptr.data_ptr);
		proc_ptr = proc_create(ptr_value, 0, tracked_pid->entry, &proc_fops);
		changes = kmalloc(sizeof(*changes), 0);
		INIT_LIST_HEAD(&changes->list);

		ptr_entry = kmalloc(sizeof(*ptr_entry), 0);
		ptr_entry->ptr = ptr.data_ptr;
		ptr_entry->size = ptr.data_size;
		ptr_entry->entry = proc_ptr;
		ptr_entry->changes = changes;

		pr_debug("Watchpoints:added pid entry: %p\n", ptr_entry->ptr);
		
		if(tracked_pid->pointers) {
			list_add(&(ptr_entry->list), &(tracked_pid->pointers)->list);
		} else {
			INIT_LIST_HEAD(&ptr_entry->list);
			tracked_pid->pointers = ptr_entry;
		}
	}
}

static void prepare_proc_entry(struct watchpoint_message ptr) {
	struct tracked_pid_list *tracked_pid = NULL;
	struct list_head *pos;
	
	list_for_each(pos, &tracked_data.list) {
		if(list_entry(pos, struct tracked_pid_list, list)->pid
			== current->pid) {
			tracked_pid = list_entry(pos, struct tracked_pid_list, list);
			break;
		}
	}

	if(!tracked_pid) {
		struct proc_dir_entry *pid_entry;
		char pid_name[30];
		
		tracked_pid = kmalloc(sizeof(*tracked_pid), 0);

		sprintf(pid_name, "%d", current->pid);
		pid_entry = proc_mkdir(pid_name, proc_watchpoints);
		
		tracked_pid->pid = current->pid;
		tracked_pid->entry = pid_entry;
		tracked_pid->pointers = NULL;

		pr_debug("added pid entry: %d\n", tracked_pid->pid);
		list_add(&(tracked_pid->list), &tracked_data.list);
	}
	
	add_ptr_entry_to_pid(tracked_pid, ptr);
}

static long add_breakpoint(struct watchpoint_message data) {
	struct perf_event *perf_watchpoint;

	if(!access_ok(VERIFY_READ, data.data_ptr, data.data_size)) {
		printk(KERN_ERR
		       "Process %d tried to access address %p\n",
		       current->pid, data.data_ptr);
		return -EINVAL;
	}

	perf_watchpoint = initialize_breakpoint(data, current->pid);

	if (IS_ERR(perf_watchpoint)) {
		printk(KERN_DEBUG "Could not set watchpoint\n");
		return -EBUSY;
	}
	
	prepare_proc_entry(data);

	return 0;	
}

static long remove_breakpoint(struct watchpoint_message data) {
	return 0;
}


static long watchpoints_ioctl(struct file *file, unsigned int cmd,
			      unsigned long ptr_message)
{
	struct watchpoint_message data;

	/* check ret_val */
	copy_from_user(&data, (void *) ptr_message, sizeof(data));


	printk(KERN_DEBUG "Received from pid %d, ptr %p, size %ld\n", current->pid,
	       data.data_ptr, data.data_size);

	switch (cmd) {
	case ADD_BREAKPOINT:
		return add_breakpoint(data);
	case REMOVE_BREAKPOINT:
		return remove_breakpoint(data);
	default:
		printk(KERN_INFO "Watchpoints was sent an unknown command %d\n", cmd);
		return -EINVAL;
	}
}


static int __init watchpoint_init(void)
{
	proc_watchpoints = proc_mkdir("watchpoints", NULL);

	INIT_LIST_HEAD(&tracked_data.list);
	misc_register(&watchpoints_misc);
	printk(KERN_INFO "Loaded module watchpoints\n");
	return 0;
}


static void __exit watchpoint_exit(void)
{
	remove_proc_entry("watchpoints", NULL);
	misc_deregister(&watchpoints_misc);
	printk(KERN_INFO "Unloaded module watchpoints\n");
}
