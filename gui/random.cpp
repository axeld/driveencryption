/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */


#include "random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <OS.h>


static uint32
hash_string(const char *string)
{
	uint32 hash = 0;
	char c;

	// we assume hash to be at least 32 bits
	while ((c = *string++) != 0) {
		hash ^= hash >> 28;
		hash <<= 4;
		hash ^= c;
	}

	return hash;
}


void
fill_random_buffer(uint8* buffer, uint32 size)
{
	// TODO: have some better number generator!
	char hostname[256];
	gethostname(hostname, sizeof(hostname));
	char user[256];
	strncpy(user, getlogin(), sizeof(user));
	uint32 base = hash_string(hostname) ^ hash_string(user);
	system_info systemInfo;

	for (uint32 i = 0; i < size; i++) {
		switch (i & 255) {
			case 0:
				get_system_info(&systemInfo);
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages);
				break;
			case 32:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.used_teams);
				break;
			case 64:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.used_ports);
				break;
			case 96:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.used_threads);
				break;
			case 128:
				get_system_info(&systemInfo);
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.boot_time);
				break;
			case 160:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.page_faults);
				break;
			case 192:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ systemInfo.used_sems);
				break;
			case 224:
				srand((uint32)system_time() ^ base ^ systemInfo.used_pages
					^ (uint32)systemInfo.cpu_clock_speed);
				break;
		}
		buffer[i] = rand() % 255;
	}
}

