/*
 * Distributed under the terms of the MIT License.
 *
 * Authors:
 *		Marcus Overhagen <Marcus@Overhagen.de>
 *		Ingo Weinhold <bonefish@users.sf.net>
 *		Axel Dörfler <axeld@pinc-software.de>
 */
#ifndef ENCRYPTED_DRIVE_H
#define ENCRYPTED_DRIVE_H


#include <Drivers.h>
#include <KernelExport.h>


// device directory and control device, "/dev" relative
#define ENCRYPTED_DRIVE_DIRECTORY_REL		"disk/virtual/encrypted"
#define ENCRYPTED_DRIVE_CONTROL_DEVICE_REL	ENCRYPTED_DRIVE_DIRECTORY_REL \
											"/control"
// device directory and control device, absolute
#define ENCRYPTED_DRIVE_DIRECTORY			"/dev/" \
											ENCRYPTED_DRIVE_DIRECTORY_REL
#define ENCRYPTED_DRIVE_CONTROL_DEVICE		"/dev/" \
											ENCRYPTED_DRIVE_CONTROL_DEVICE_REL

#define ENCRYPTED_DRIVE_IOCTL_BASE			(B_DEVICE_OP_CODES_END + 10001)

#define ENCRYPTED_DRIVE_SALT_SIZE			64

enum {
	ENCRYPTED_DRIVE_REGISTER_FILE	= ENCRYPTED_DRIVE_IOCTL_BASE,
		// on control device: encrypted_drive_info*, fills in device_name
	ENCRYPTED_DRIVE_UNREGISTER_FILE,
		// on data device: none
	ENCRYPTED_DRIVE_INITIALIZE_FILE,
	ENCRYPTED_DRIVE_GET_INFO,
		// on data device: encrypted_drive_info*
	ENCRYPTED_DRIVE_ENCRYPT_BUFFER,
	ENCRYPTED_DRIVE_DECRYPT_BUFFER,
		// on control device: encrypted_drive_info*
};

#define ENCRYPTED_DRIVE_MAGIC	'EdIn'

typedef struct encrypted_drive_info {
	uint32			magic;
	size_t			drive_info_size;
	char			file_name[B_PATH_NAME_LENGTH];
	char			device_name[B_PATH_NAME_LENGTH];
	const uint8*	key;
	uint32			key_length;
	const uint8*	random_data;
	uint32			random_length;
	uint8*			buffer;
	uint32			buffer_length;
	bool			read_only;
	bool			hidden;
} encrypted_drive_info;

#endif	// ENCRYPTED_DRIVE_H
