obj-m += watchpoints.o
CFLAGS_watchpoints.o := -Wall -W -Werror -Wextra -Wno-unused-parameter

all: watchpoints test

watchpoints:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	@printf "\n#########################\n##   Compiling tests   ##\n#########################\n"
	python3 tests/compile_tests.py
	@printf "\n#########################\n##    Running tests    ##\n#########################\n"
	@printf "Needing root access for tests : \n"
	sudo python3 tests/run_tests.py
