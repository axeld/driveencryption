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


const size_t kTestSize = 65536*1024;
const size_t kBufferSize = 65536;


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

	init_crypt();

	Worker worker;
	worker.Init();

	VolumeCryptContext context;
	status_t status;

	uint8* block = (uint8*)malloc(kBufferSize);
	if (block == NULL)
		return 1;

	if (initialize) {
		// generate random data to be used as salt and AES keys
		uint8 random[2048];
		fill_random_buffer(random, sizeof(random));

		status = context.Setup(fd, key, keyLength, random, sizeof(random));
		printf("setup: %s\n", strerror(status));

		if (status == B_OK) {
			// write test data
			for (int i = 0; i < kBufferSize; i++)
				block[i] = i % 256;

			off_t offset = context.Offset();
			size_t written = 0;
			while (written < kTestSize) {
				size_t toWrite = min_c(kBufferSize, kTestSize - written);

//				context.EncryptBlock(block, toWrite, offset / BLOCK_SIZE);
				EncryptTask task(context, block, toWrite, offset / BLOCK_SIZE);
				worker.AddTask(task);
				worker.WaitFor(task);
				write_pos(fd, offset, block, toWrite);

				written += toWrite;
				offset += toWrite;
			}
		}
	} else {
		status = context.Detect(fd, key, keyLength);
		printf("detect: %s, offset %lld\n", strerror(status), context.Offset());
	}

	if (status == B_OK) {
		off_t offset = context.Offset();
		size_t totalBytesRead = 0;
		while (totalBytesRead < kTestSize) {
			size_t toRead = min_c(kBufferSize, kTestSize - totalBytesRead);
			ssize_t bytesRead = read_pos(fd, offset, block, toRead);
			if (bytesRead == toRead) {
//				context.DecryptBlock(block, toRead, offset / BLOCK_SIZE);
				DecryptTask task(context, block, toRead, offset / BLOCK_SIZE);
				worker.AddTask(task);
				worker.WaitFor(task);

				for (int i = 0; i < toRead; i++) {
					if (block[i] != i % 256) {
						fprintf(stderr, "Block at %d is corrupt!\n", i);
						dump_block((char*)&block[i], min_c(128, toRead - i),
							"Corrupt");
						break;
					}
				}
			} else {
				fprintf(stderr, "Could not read block: %s\n",
					strerror(bytesRead));
				break;
			}

			totalBytesRead += toRead;
			offset += toRead;
		}
	}
	free(block);

	close(fd);
	return 0;
}
