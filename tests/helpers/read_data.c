#include <stdio.h>
#include <stdlib.h>

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
