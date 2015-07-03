#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <watchpoints.h>

#include "helpers/read_data.c"
#include "helpers/launcher.c"


void *create_and_modify_data()
{
	char *track_me = malloc(sizeof(char) * 4);
	struct watchpoint_message data;
	int file_desc;

	data.data_ptr = track_me;
	data.data_size = 4 * sizeof(char);

	sprintf(track_me, "%s", "1234");

	file_desc = open("/dev/watchpoints", O_RDONLY);
	CU_ASSERT_NOT_EQUAL(file_desc, -1);

	/* enable data tracking */
	CU_ASSERT_FALSE(ioctl(file_desc, WATCHPOINT_ADD, &data));

	sprintf(track_me, "%s", "5323");
	
	/* resize data */
	data.data_size = 8 * sizeof(char);
	track_me = realloc(track_me, data.data_size);	
	CU_ASSERT_PTR_NOT_NULL_FATAL(track_me);

	data.new_data_ptr = track_me;
	CU_ASSERT_FALSE(ioctl(file_desc, WATCHPOINT_RESIZE, &data));
	
	sprintf(track_me, "%s", "43211234");

	/* disable data tracking */
	CU_ASSERT_FALSE(ioctl(file_desc, WATCHPOINT_REMOVE, &data));

	sprintf(track_me, "%s", "0000");

	return track_me;
}


void test_resize()
{
	char proc_directory[255];
	FILE *proc_values;

	void *track_me = create_and_modify_data();

	sprintf(proc_directory, "/proc/watchpoints/%d/%016lx", getpid(),
		(long unsigned int) track_me);

	proc_values = fopen(proc_directory, "r");

	CU_ASSERT_STRING_EQUAL(get_data(proc_values), "5323");
	CU_ASSERT_STRING_EQUAL(get_data(proc_values), "43211234");
	CU_ASSERT_EQUAL(fgetc(proc_values), EOF);

	fclose(proc_values);

	free((void *) track_me);
}


int main()
{
	return run_suite("test_resize",
			 "test Resize of data",
			 test_resize);
}
