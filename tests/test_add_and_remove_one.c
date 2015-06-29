#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>

#include <watchpoints.h>

#include "CUnit/Basic.h"


void print(int num) {
	printf("%d\n", num);
}


void test_add_and_remove() {
	int file_desc;
	int ret_val;
	char buff[10];
	/*char *results;*/
	/*char *p;*/
	struct watchpoint_message data;
	
	pid_t pid = getpid();
	long track_me = 12098;
	
	memset(buff, '\0', sizeof(buff));
	
	data.pid = pid;
	data.data_ptr = (long) &track_me;
	data.data_size = sizeof(long);
	 
	file_desc = open(DEVICE_PATH, O_RDONLY);
	CU_ASSERT_NOT_EQUAL(file_desc, -1);

	ret_val = ioctl(file_desc, 1, &data);
	CU_ASSERT_FALSE(ret_val);
	
	if(track_me) {
		track_me = 532;
	}
	
	if(track_me) {
		track_me = 12;
	}
	
	ret_val = ioctl(file_desc, 2, &data);
	CU_ASSERT_FALSE(ret_val);
	
	/*while( read(file_desc, buff, 1 )) {
		printf("%s", buff);
	}*/
	
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
   if (NULL == CU_add_test(pSuite, "test Addition and removal", test_add_and_remove)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}
