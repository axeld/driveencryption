/*
 * Copyright 2009-2026, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "crypt.h"
#include "random.h"
#include "Volume.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


const size_t kTestSize = 1024;//65536;//*1024;
const size_t kBufferSize = 65536;


extern "C" void
dump_block(const char *buffer, int size, const char *prefix)
{
	const int DUMPED_BLOCK_SIZE = 16;
	int i;

	for (i = 0; i < size;) {
		int start = i;

		printf(prefix);
		for (; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (!(i % 4))
				printf(" ");

			if (i >= size)
				printf("  ");
			else
				printf("%02x", *(unsigned char *)(buffer + i));
		}
		printf("  ");

		for (i = start; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (i < size) {
				char c = buffer[i];

				if (c < 30)
					printf(".");
				else
					printf("%c", c);
			} else
				break;
		}
		printf("\n");
	}
}


int
main(int argc, char** argv)
{
	if (argc < 3) {
		fprintf(stderr, "%s <device/image> <key> {init|change|resize} [newPassword|newSize]\n", argv[0]);
		return 1;
	}

	bool initialize = argc > 3 && !strcmp(argv[3], "init");
	bool changePassword = argc > 4 && !strcmp(argv[3], "change");
	bool resize = argc > 4 && !strcmp(argv[3], "resize");

	int fd = open(argv[1], initialize || changePassword || resize ? O_RDWR : O_RDONLY);
	if (fd < 0)
		return 1;

	uint8* key = (uint8*)argv[2];
	size_t keyLength = strlen(argv[2]);

	CryptContext context;
	Volume volume(context);
	status_t status;

	uint8* block = (uint8*)malloc(kBufferSize);
	if (block == NULL)
		return 1;

	if (initialize) {
		// generate random data to be used as salt and AES keys
		uint8 random[2048];
		fill_random_buffer(random, sizeof(random));

		status = volume.Setup(fd, key, keyLength, random, sizeof(random));
		printf("setup: %s\n", strerror(status));

		if (status == B_OK) {
			// write test data
			for (int i = 0; i < kBufferSize; i++)
				block[i] = i % 256;

			off_t offset = volume.Offset();
			size_t written = 0;
			while (written < kTestSize) {
				size_t toWrite = min_c(kBufferSize, kTestSize - written);

				context.EncryptBlock(block, toWrite, offset / BLOCK_SIZE);
				write_pos(fd, offset, block, toWrite);

				written += toWrite;
				offset += toWrite;
			}
		}
	} else if (changePassword) {
		uint8* newKey = (uint8*)argv[4];
		size_t newKeyLength = strlen(argv[4]);
		status = volume.SetPassword(fd, key, keyLength, newKey, newKeyLength);
		if (status != B_OK) {
			fprintf(stderr, "Could not set password: %s\n",
				strerror(status));
			return 1;
		}

//		status = context.Detect(fd, newKey, newKeyLength);
		printf("-> %s, offset %lld\n", strerror(status), volume.Offset());
	} else if (resize) {
		off_t newSize = atoll(argv[4]);
		status = volume.Resize(fd, key, keyLength, newSize);
		printf("resize: %s, offset %lld, size %lld\n", strerror(status), volume.Offset(), volume.Size());
	} else {
		status = volume.Detect(fd, key, keyLength);
		printf("detect: %s, offset %lld, size %lld\n", strerror(status), volume.Offset(), volume.Size());
	}

#if 0
	if (status == B_OK) {
		off_t offset = volume.Offset();
		size_t totalBytesRead = 0;
		while (totalBytesRead < kTestSize) {
			size_t toRead = min_c(kBufferSize, kTestSize - totalBytesRead);
			ssize_t bytesRead = read_pos(fd, offset, block, toRead);
			if (bytesRead == toRead) {
				context.DecryptBlock(block, toRead, offset / BLOCK_SIZE);

				dump_block((char*)block, toRead, "READ");

//				for (int i = 0; i < toRead; i++) {
//					if (block[i] != i % 256) {
//						fprintf(stderr, "Block at %d is corrupt!\n", i);
//						dump_block((char*)&block[i], min_c(128, toRead - i),
//							"Corrupt");
//						break;
//					}
//				}
			} else {
				fprintf(stderr, "Could not read block: %s\n",
					strerror(bytesRead));
				break;
			}

			totalBytesRead += toRead;
			offset += toRead;
		}
	}
#endif
	free(block);

	close(fd);
	return 0;
}
