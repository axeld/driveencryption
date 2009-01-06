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


extern "C" void
dump_block(const char *buffer, int size, const char *prefix)
{
	const int DUMPED_BLOCK_SIZE = 16;
	int i;
	
	for (i = 0; i < size;) {
		int start = i;

		dprintf(prefix);
		for (; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (!(i % 4))
				dprintf(" ");

			if (i >= size)
				dprintf("  ");
			else
				dprintf("%02x", *(unsigned char *)(buffer + i));
		}
		dprintf("  ");

		for (i = start; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (i < size) {
				char c = buffer[i];

				if (c < 30)
					dprintf(".");
				else
					dprintf("%c", c);
			} else
				break;
		}
		dprintf("\n");
	}
}


int
main(int argc, char** argv)
{
	if (argc < 3)
		return 1;

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 1;

	VolumeCryptContext context;

	status_t status = context.Detect(fd, (uint8*)argv[2],
		strlen(argv[2]));
	printf("detect: %s\n", strerror(status));

	if (status == B_OK) {
		uint8 block[512];
		read_pos(fd, context.Offset(), block, 512);
		context.Decrypt(block, 512, 0);

		dump_block((char*)block, 512, "");
	}

	close(fd);
	return 0;
}
