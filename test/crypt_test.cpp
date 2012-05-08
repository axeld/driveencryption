/*
 * Copyright 2009-2012, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "crypt.h"

#include "random.h"

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

	bool initialize = argc > 3 && !strcmp(argv[3], "init");

	int fd = open(argv[1], initialize ? O_RDWR : O_RDONLY);
	if (fd < 0)
		return 1;

	uint8* key = (uint8*)argv[2];
	size_t keyLength = strlen(argv[2]);

	VolumeCryptContext context;
	status_t status;

	if (initialize) {
		// generate random data to be used as salt and AES keys
		uint8 random[2048];
		fill_random_buffer(random, sizeof(random));

		status = context.Setup(fd, key, keyLength, random, sizeof(random));
		printf("setup: %s\n", strerror(status));

		if (status == B_OK) {
			// write test data
			uint8 block[512];
			for (int i = 0; i < sizeof(block); i++)
				block[i] = i % 256;

			context.EncryptBlock(block, 512, context.Offset() / 512);
			write_pos(fd, context.Offset(), block, 512);
		}
	} else {
		status = context.Detect(fd, key, keyLength);
		printf("detect: %s, offset %lld\n", strerror(status), context.Offset());
	}

	if (status == B_OK) {
		uint8 block[512];
		read_pos(fd, context.Offset(), block, 512);
		context.DecryptBlock(block, 512, context.Offset() / 512);

		dump_block((char*)block, 512, "");
	}

	close(fd);
	return 0;
}
