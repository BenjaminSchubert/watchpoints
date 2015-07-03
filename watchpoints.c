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


/*
 * structs prototypes
 */

/* tracks changes */
struct tracked_changes_list;

/* tracks pointers */
struct tracked_pointer_list;

/* tracks pids */
struct tracked_pid_list;


/*
 * Function prototypes
 */

/* handles the watchpoint event */
static void watchpoint_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs);

/* handles the ioctl event */
static long watchpoints_ioctl(struct file *file, unsigned int cmd,
			      long unsigned ptr_message);

/* handles the opening of a pointer file */
static int proc_open(struct inode *inode, struct file *file);

/* handles the display of information on the pointer file */
static int proc_display(struct seq_file *m, void *v);

/* initialization function for the module */
static int __init watchpoint_init(void);

/* cleanup function for the module */
static void __exit watchpoint_exit(void);

/* gets the head of the pointer list for the specified pid */
struct tracked_pointer_list *get_pointer_list_for_pid(u64 pid);

/* extract from the list the pointer corresponding to the ptr value */
struct tracked_pointer_list *get_pointer_from_pointer_list(struct
							   tracked_pointer_list
							   *pointer_list,
							   u64 ptr);

/* initiliazes the watchpoint */
static struct perf_event *initialize_watchpoint(struct watchpoint_message
						data, pid_t pid);

/* adds a new pointer to the list of pointers tracked by the pid */
static void add_ptr_entry_to_pid(struct tracked_pid_list *tracked_pid,
				 struct perf_event *event, long size);

/* creates a new proc entry for the pid of ptr*/
static void prepare_proc_entry(struct perf_event *event, long size);

/* adds a new watchpoint */
static long add_watchpoint(struct watchpoint_message data);

/* removes a watchpoint */
static long remove_watchpoint(struct watchpoint_message data);

/* frees all changes recorded and returns the size used by the data */
static size_t clean_tracked_changes_data(struct tracked_changes_list
					 *changes);

/* frees all pointers recorded and returns the size used by them */
static size_t clean_tracked_pointer_data(struct tracked_pointer_list
					 *pointers, struct proc_dir_entry
					 *parent_entry);

/* frees all pids recorded */
static void clean_tracked_pid_data(void);


/*
 * Struct declarations
 */

/* representation of a change in data */
struct tracked_changes_list {
	/* new value of the data */
	u8 *data;
	/* size of the data chunk */
	size_t data_size;
	/* list to which the data belongs */
	struct list_head list;
};

/* information about a pointer tracked by a watchpoint */
struct tracked_pointer_list {
	/* pointer tracked */
	struct perf_event *event;
	/* size of the pointer data area */
	size_t size;
	/* entry in the proc directory for the pointer */
	struct proc_dir_entry *entry;
	/* list to which the pointer belongs */
	struct list_head list;
	/* changes to the data to which the pointer points */
	struct tracked_changes_list *changes;
};

/* information about a pid tracked */
struct tracked_pid_list {
	/* pid tracked */
	pid_t pid;
	/* entry in the proc directory for the pid */
	struct proc_dir_entry *entry;
	/* list to which the pid belongs */
	struct list_head list;
	/* list of pointers to track for this pid */
	struct tracked_pointer_list *pointers;
};

/* file operations for the watchpoint entry in /dev */
const struct file_operations ctrl_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.unlocked_ioctl = watchpoints_ioctl,
	.open = NULL,
	.release = NULL,
};

/* informations about the watchpoint entry in /dev */
struct miscdevice watchpoints_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &ctrl_fops
};

/* file operations for the pointer entries in /proc/watchpoints/pid */
const struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.open = proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release
};


/*
 * Globals declaration
 */

/* entry in the proc directory for the module */
struct proc_dir_entry *proc_watchpoints;

/* centralizes everything that is tracked by the module */
struct tracked_pid_list tracked_data;


/* register the initialization and cleanup functions */
module_init(watchpoint_init);
module_exit(watchpoint_exit);


static int proc_display(struct seq_file *m, void *v)
{
	struct tracked_pointer_list *pointer =
	    (struct tracked_pointer_list *) m->private;
	struct tracked_changes_list *change;

	list_for_each_entry(change, &pointer->changes->list, list) {
		long counter;
		seq_printf(m, "%lu ", change->data_size);
		for (counter = 0; counter < change->data_size; counter++) {
			seq_printf(m, "%c", change->data[counter]);
		}
	}

	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_display, PDE_DATA(inode));
}


struct tracked_pointer_list *get_pointer_list_for_pid(u64 pid)
{
	struct tracked_pid_list *pid_list;

	list_for_each_entry(pid_list, &tracked_data.list, list) {
		if (pid_list->pid == pid) {
			return pid_list->pointers;
		}
	}

	return NULL;
}

struct tracked_pointer_list *get_pointer_from_pointer_list(struct
							   tracked_pointer_list
							   *pointer_list,
							   u64 ptr)
{
	struct tracked_pointer_list *pointer;

	list_for_each_entry(pointer, &pointer_list->list, list) {
		if (pointer->event->attr.bp_addr == ptr) {
			return pointer;
		}
	}

	return NULL;
}

static void watchpoint_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
	struct tracked_pointer_list *pointer_list;
	struct tracked_pointer_list *pointer;
	struct tracked_changes_list *new_change;

	pointer_list = get_pointer_list_for_pid(bp->ctx->task->pid);
	pointer =
	    get_pointer_from_pointer_list(pointer_list, bp->attr.bp_addr);

	new_change = kmalloc(sizeof(*new_change), 0);
	new_change->data = kmalloc((pointer->size + 1) * sizeof(u8), 0);
	new_change->data[pointer->size] = '\0';

	pr_debug("The pointer is %016llx with size of %ld\n",
		 pointer->event->attr.bp_addr, pointer->size);

	copy_from_user(new_change->data,
		       (void *) pointer->event->attr.bp_addr,
		       pointer->size);
	pr_debug("Process %d at position %016llx, new value: %s\n",
		 bp->ctx->task->pid, pointer->event->attr.bp_addr,
		 new_change->data);

	new_change->data_size = pointer->size;
	list_add_tail(&(new_change->list), &pointer->changes->list);
}

static struct perf_event *initialize_watchpoint(struct watchpoint_message
						data, pid_t pid)
{
	struct perf_event *perf_watchpoint;
	struct task_struct *tsk;
	struct perf_event_attr attr;

	/* Initialize watchpoint */
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


static void add_ptr_entry_to_pid(struct tracked_pid_list *tracked_pid,
				 struct perf_event *event, long size)
{
	struct tracked_pointer_list *ptr_entry;
	int ptr_entry_created = 0;

	list_for_each_entry(ptr_entry, &tracked_pid->pointers->list, list) {
		if (ptr_entry->event->attr.bp_addr == event->attr.bp_addr) {
			ptr_entry_created = 1;
			break;
		}
	}

	if (!ptr_entry_created) {
		struct proc_dir_entry *proc_ptr;
		struct tracked_pointer_list *ptr_entry;
		struct tracked_changes_list *changes;
		char ptr_value[2 * sizeof(long) + 1];

		changes = kmalloc(sizeof(*changes), 0);

		sprintf(ptr_value, "%016llx", event->attr.bp_addr);

		ptr_entry = kmalloc(sizeof(*ptr_entry), 0);
		ptr_entry->event = event;
		ptr_entry->size = size;
		ptr_entry->changes = changes;
		INIT_LIST_HEAD(&changes->list);

		pr_debug("added ptr entry: %s\n", ptr_value);

		list_add_tail(&(ptr_entry->list),
			      &tracked_pid->pointers->list);

		proc_ptr =
		    proc_create_data(ptr_value, 0, tracked_pid->entry,
				     &proc_fops, ptr_entry);
		ptr_entry->entry = proc_ptr;
	}
}

static void prepare_proc_entry(struct perf_event *event, long size)
{
	struct tracked_pid_list *tracked_pid = NULL;
	struct tracked_pid_list *pid_list;

	list_for_each_entry(pid_list, &tracked_data.list, list) {
		if (pid_list->pid == current->pid) {
			tracked_pid = pid_list;
			break;
		}
	}

	if (!tracked_pid) {
		struct proc_dir_entry *pid_entry;
		struct tracked_pointer_list *pointers;
		char pid_name[30];

		tracked_pid = kmalloc(sizeof(*tracked_pid), 0);
		pointers = kmalloc(sizeof(*pointers), 0);

		sprintf(pid_name, "%d", current->pid);
		pid_entry = proc_mkdir(pid_name, proc_watchpoints);

		tracked_pid->pid = current->pid;
		tracked_pid->entry = pid_entry;
		tracked_pid->pointers = pointers;
		INIT_LIST_HEAD(&pointers->list);

		pr_debug("added pid entry: %d\n", tracked_pid->pid);
		list_add_tail(&(tracked_pid->list), &tracked_data.list);
	}

	add_ptr_entry_to_pid(tracked_pid, event, size);
}

static long add_watchpoint(struct watchpoint_message data)
{
	struct perf_event *perf_watchpoint;

	perf_watchpoint = initialize_watchpoint(data, current->pid);

	if (IS_ERR(perf_watchpoint)) {
		pr_info("Could not set watchpoint\n");
		return -EBUSY;
	}

	prepare_proc_entry(perf_watchpoint, data.data_size);

	return 0;
}

static long remove_watchpoint(struct watchpoint_message data)
{
	struct tracked_pointer_list *pointers_for_pid;
	struct tracked_pointer_list *pointer;

	pointers_for_pid = get_pointer_list_for_pid(current->pid);
	if (!pointers_for_pid)
		goto fail;

	pointer =
	    get_pointer_from_pointer_list(pointers_for_pid,
					  (u64) data.data_ptr);
	if (!pointer)
		goto fail;

	unregister_hw_breakpoint(pointer->event);
	pr_debug("Removed watchpoint on %016llx for pid %d\n",
		 (u64) data.data_ptr, current->pid);

	return 0;

      fail:
	return -EINVAL;
}


static long watchpoints_ioctl(struct file *file, unsigned int cmd,
			      unsigned long ptr_message)
{
	struct watchpoint_message data;
	long ret_val;

	/* TODO: check ret_val */
	copy_from_user(&data, (void *) ptr_message, sizeof(data));

	pr_info("Received from pid %d, ptr %p, size %ld\n", current->pid,
		data.data_ptr, data.data_size);

	switch (cmd) {
	case ADD_WATCHPOINT:
		ret_val = add_watchpoint(data);
		break;
	case REMOVE_WATCHPOINT:
		ret_val = remove_watchpoint(data);
		break;
	default:
		pr_info("Watchpoints was sent an unknown command %d\n",
			cmd);
		ret_val = -EINVAL;
		break;
	}

	return ret_val;
}


static size_t clean_tracked_changes_data(struct tracked_changes_list
					 *changes)
{
	struct tracked_changes_list *change;
	struct tracked_changes_list *temp;
	size_t memory_used = 0;

	list_for_each_entry_safe(change, temp, &changes->list, list) {
		memory_used += ksize(change->data);
		kfree(change->data);
		memory_used += ksize(change);
		kfree(change);
	}

	return memory_used;
}

static size_t clean_tracked_pointer_data(struct tracked_pointer_list
					 *pointers, struct proc_dir_entry
					 *parent_entry)
{
	struct tracked_pointer_list *pointer;
	struct tracked_pointer_list *temp;
	size_t memory_used = 0;

	list_for_each_entry_safe(pointer, temp, &pointers->list, list) {
		char ptr_value[2 * sizeof(long) + 1];

		memory_used +=
		    clean_tracked_changes_data(pointer->changes);

		sprintf(ptr_value, "%016llx",
			pointer->event->attr.bp_addr);
		remove_proc_entry(ptr_value, parent_entry);

		list_del(&pointer->list);
		memory_used += ksize(pointer);
		kfree(pointer);
	}

	return memory_used;
}

static void clean_tracked_pid_data(void)
{
	struct tracked_pid_list *pid;
	struct tracked_pid_list *temp;
	size_t memory_used = 0;

	list_for_each_entry_safe(pid, temp, &tracked_data.list, list) {
		char pid_name[30];

		memory_used +=
		    clean_tracked_pointer_data(pid->pointers, pid->entry);

		sprintf(pid_name, "%d", pid->pid);
		remove_proc_entry(pid_name, proc_watchpoints);

		list_del(&pid->list);
		memory_used += ksize(pid);
		kfree(pid);
	}
	pr_debug("using %lu bytes\n", memory_used);
}

static int __init watchpoint_init(void)
{
	proc_watchpoints = proc_mkdir("watchpoints", NULL);

	INIT_LIST_HEAD(&tracked_data.list);
	misc_register(&watchpoints_misc);
	pr_info("module successfully loaded\n");
	return 0;
}


static void __exit watchpoint_exit(void)
{
	clean_tracked_pid_data();
	remove_proc_entry("watchpoints", NULL);
	misc_deregister(&watchpoints_misc);
	pr_info("module successfully unloaded\n");
}
