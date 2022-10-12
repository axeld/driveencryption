/*
 * Copyright 2007-2022, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef UTILITY_H
#define UTILITY_H


#include <String.h>


BString SizeString(off_t bytes);
off_t ParseSize(const char* string);


#endif	// UTILITY_H
