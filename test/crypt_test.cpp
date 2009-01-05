/*
 * Copyright 2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "crypt.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern "C" void
dprintf(const char *format,...)
{
	va_list args;
	va_start(args, format);
	printf("\33[34m");
	vprintf(format, args);
	printf("\33[0m");
	fflush(stdout);
	va_end(args);
}


int
main(int argc, char** argv)
{
	if (argc < 3)
		return 1;

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 1;

	crypt_context context;
	init_context(context);

	status_t status = detect_drive(context, fd, (uint8*)argv[2], strlen(argv[2]));
	printf("detect: %s\n", strerror(status));

	close(fd);
	return 0;
}
