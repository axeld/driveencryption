/*
 * Copyright 2007-2022, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "utility.h"

#include <ctype.h>
#include <stdlib.h>

#include <String.h>


static const off_t kGigaByte = 1024LL * 1024 * 1024;
static const off_t kMegaByte = 1024LL * 1024;


BString
SizeString(off_t bytes)
{
	BString string;

	if (bytes < 1024)
		string.SetToFormat("%Ld bytes", bytes);
	else {
		const char *units[] = {"KB", "MB", "GB", "TB", NULL};
		double size = bytes;
		int32 i = -1;

		do {
			size /= 1024.0;
			i++;
		} while (size >= 1024 && units[i + 1]);

		string.SetToFormat("%.1f %s", size, units[i]);
	}

	return string;
}


off_t
ParseSize(const char* string)
{
	char* end;
	double size = strtod(string, &end);
	off_t bytes = off_t(size);
	if (size == 0.0) {
		// for hex numbers
		bytes = strtoll(string, &end, 0);
		size = (double)bytes;
	}

	if (end == NULL)
		return bytes;

	while (isspace(end[0])) {
		end++;
	}

	switch (end[0]) {
		case 'K':
		case 'k':
			return off_t(size * 1024);
		case 'M':
		case 'm':
			return off_t(size * kMegaByte);
		case 'G':
		case 'g':
			return off_t(size * kGigaByte);
		case 'T':
		case 't':
			return off_t(size * 1024 * kGigaByte);
	}

	return bytes;
}
