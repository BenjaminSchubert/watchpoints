#!/usr/bin/env python3
# -*- Coding: UTF-8 -*-


import os
import subprocess


def compile(program):
	try:
		subprocess.check_output(
			[
				"gcc",
				"-std=gnu89",
				"-Wall",
				"-Werror",
				"-Wextra",
				"-pedantic",
				"-Wfatal-errors",
				"-I", os.getcwd(),
				"-o", "build/{}".format(program.rstrip(".c")),
				program,
				"-lcunit",
			],
			cwd=os.path.join(os.getcwd(), "tests"),
			stderr=subprocess.STDOUT
		)
	except subprocess.CalledProcessError as exc:
		print(exc.output.decode())
		return 1


def main():
	os.makedirs(os.path.join(os.getcwd(), "tests/build"), exist_ok=True)
	
	files = [_file_ for _file_ in os.listdir(os.path.join(os.getcwd(), "tests")) if _file_.endswith(".c")]

	return any(map(compile, files))


if __name__ == "__main__":
	exit(main())
