#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <watchpoints.h>

#include "CUnit/Basic.h"


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
	CU_ASSERT_FALSE(ioctl(file_desc, ADD_WATCHPOINT, &data));

	sprintf(track_me, "%s", "5323");
	sprintf(track_me, "%s", "4321");

	/* disable data tracking */
	CU_ASSERT_FALSE(ioctl(file_desc, REMOVE_WATCHPOINT, &data));

	sprintf(track_me, "%s", "0000");

	return track_me;
}


char *get_data(FILE * results)
{
	char ch;
	char *length_char = NULL;
	long length;
	char *result;
	int counter = 0;

	while ((ch = fgetc(results)) != EOF) {
		if (ch == ' ') {
			break;
		}
		length_char =
		    realloc(length_char, ++counter * sizeof(char));
		sprintf(length_char + counter - 1, "%c", ch);
	}
	sscanf(length_char, "%ld", &length);

	result = malloc((length + 1) * sizeof(char));
	fgets(result, length + 1, results);

	free(length_char);

	return result;
}


void test_add_and_remove()
{
	char proc_directory[255];
	FILE *proc_values;

	void *track_me = create_and_modify_data();

	sprintf(proc_directory, "/proc/watchpoints/%d/%016lx", getpid(),
		(long unsigned int) track_me);

	proc_values = fopen(proc_directory, "r");

	CU_ASSERT_STRING_EQUAL(get_data(proc_values), "5323");
	CU_ASSERT_STRING_EQUAL(get_data(proc_values), "4321");
	CU_ASSERT_EQUAL(fgetc(proc_values), EOF);

	fclose(proc_values);

	free((void *) track_me);
}


int main()
{
	CU_pSuite pSuite = NULL;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	pSuite = CU_add_suite("test_add_remove_one", NULL, NULL);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	/* add the tests to the suite */
	if (NULL ==
	    CU_add_test(pSuite, "test Addition and removal",
			test_add_and_remove)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
