/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef MOUNT_SUPPORT_H
#define MOUNT_SUPPORT_H


#include <SupportDefs.h>


status_t mount_device(const char* device, const char* mountAt);

#endif	// MOUNT_SUPPORT_H
