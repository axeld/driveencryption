/*
 * Copyright 2003-2008, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include <Path.h>
#include <File.h>
#include <Entry.h>
#include <Directory.h>
#include <String.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __HAIKU__
#	include <fs_volume.h>
#endif


static bool
isBootBlock(const uint8 *block)
{
	return block[0x1fe] == 0x55
		&& block[0x1ff] == 0xaa;
}


static status_t
getFileSystem(const char *path, BString &fileSystem, BString &label)
{
	BFile file;
	status_t status = file.SetTo(path, B_READ_ONLY);
	if (status < B_OK)
		return status;

	char block[2048];
	if (file.ReadAt(0, block, 2048) < B_OK)
		return B_ERROR;

	/*** check for BFS ***/

	if (!strncmp(block + 512 + 32, "1SFB", 4)) {
		fileSystem = "bfs";
		label = block + 512;

		return B_OK;
	}

	/*** check for NTFS ***/
	
	if (!strncmp(block + 3, "NTFS", 4) && isBootBlock((uint8 *)block)) {
		fileSystem = "ntfs";
		label = "NTFS volume";

		return B_OK;
	}
	
	/*** check for FAT32 ***/
	
	if (strncmp(block + 3, "HPFS", 4) && isBootBlock((uint8 *)block)
		&& block[0x10] > 0 && block[0x10] < 8) {
		fileSystem = "dos";
		label = "FAT volume";

		return B_OK;
	}

	/*** check for ISO-9660 ***/

	off_t offset = 0;
	do {
		if (strncmp(block + 1, "CD001", 5) == 0) {
			fileSystem = "iso9660";
			
			int32 index = 40 + 31;
			while (block[index] == ' ')
				block[index--] = '\0';

			label = block + 40;

			return B_OK;
		}
	} while ((offset += 2048) < 0x10000 && file.ReadAt(offset, block, 2048) == 2048);

	return B_ERROR;
}


status_t
mount_device(const char *file, const char* mountAt)
{
	BString fileSystem, label;
	if (getFileSystem(file, fileSystem, label) < B_OK)
		return B_BAD_VALUE;

	BString target;
	if (mountAt != NULL && mountAt[0])
		target = mountAt;
	else {
		if (label == "")
			label = "secure";
		target = "/";
		target << label;
	}

	char name[B_FILE_NAME_LENGTH];
	BEntry entry;
	int32 i = 0;

	do {
		if (i++ == 0)
			sprintf(name, "%s", target.String());
		else
			sprintf(name, "%s_%ld", label.String(), i);

		entry.SetTo(name);
		if (entry.Exists() && entry.IsDirectory()) {
			BDirectory directory(&entry);
			if (directory.InitCheck() == B_OK && directory.CountEntries() == 0)
				break;
		}
	} while (entry.Exists() && i < 42);

	create_directory(name, 0755);

#ifdef __HAIKU__
	status_t status = fs_mount_volume(name, file, fileSystem.String(), 0, NULL);
	if (status != B_OK)
		return status;
#else
	if (mount(fileSystem.String(), name, file, 0, NULL, 0) < 0)
		return errno;
#endif

	return B_OK;
}

