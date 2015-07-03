#!/usr/bin/env python3
# -*- Coding: UTF-8 -*-


from contextlib import suppress
import os
import subprocess


module = os.path.join(os.getcwd(), "watchpoints.ko")
cwd = os.path.join(os.getcwd(), "tests/build")


class Results:
	report = {
		"Total": 0,
		"Ran": 0,
		"Passed": 0,
		"Failed": 0
	}

	suites = report.copy()
	tests = report.copy()
	asserts = report.copy()
	time_spent = 0


def run(program, result):
	return_value = 0

	subprocess.check_output(["insmod", module])	
	try:
		output = subprocess.check_output(["./{}".format(program)], cwd=cwd)
	finally:
		subprocess.check_output(["rmmod", module])
	print(output.decode())
	show_next_line = False
	for entry in output.decode().split("\n"):
		entry = entry.strip()

		if show_next_line:
			print("\t\t",entry)
			show_next_line = False

		elif entry.startswith("Suite:"):
			name = " ".join(entry.split()[1:])
			suite = name
			print("\nSuite:", suite)

		elif entry.startswith("Test:"):
			name = " ".join(entry.split()[1:-1])
			test_result = entry.split()[-1].strip(".")
			print("\tTest:", name, "...", test_result)
			if(test_result):
				show_next_line = True

		elif entry.startswith("suites") or entry.startswith("tests") or entry.startswith("asserts"):
			results = entry.split()
			values = getattr(result, results[0])
			values["Total"] += int(results[1])
			values["Ran"] += int(results[2])
			try:
				values["Passed"] += int(results[3])
			except ValueError:
				values["Passed"] = results[3]
			values["Failed"] += int(results[4])
			if(int(results[4])):
				return_value = 1

		elif entry.startswith("Elapsed time"):
			time = entry.split(" ")[-2]
			result.time_spent += float(time)

	return return_value


def print_summary(result):
	print("\n\nElapsed time : ", result.time_spent)
	print("\nSummary :\tType\tTotal\tRan\tPassed\tFailed")
	for entry in ["suites", "tests", "asserts"]:
		values = getattr(result, entry)
		print("\t\t{}\t{}\t{}\t{}\t{}".format(
			entry,
			values["Total"],
			values["Ran"],
			values["Passed"],
			values["Failed"]			
		))


def main():
	result = Results()
	return_values = [run(_file_, result) for _file_ in os.listdir(cwd)]
	print_summary(result)
	return any(return_values)

if __name__ == "__main__":
	exit(main())
