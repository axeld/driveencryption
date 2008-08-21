/*
 * Copyright 2007-2008, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "encrypted_drive.h"
#include "random.h"

extern "C" const char *__progname;

const char* kProgramName = __progname;


static void
print_usage(bool error = false)
{
	fprintf(error ? stderr : stdout,
		"Usage: %s [ --install ] [--read-only] [ --key <password> ] <file>\n"
		"       %s --uninstall  <device>\n"
		"       %s --init [--key <password>] <file>\n"
		"       %s --list\n"
		"       %s ( --help | -h )\n",
		kProgramName, kProgramName, kProgramName, kProgramName, kProgramName);
}


static void
test_for_driver()
{
	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return;
	}

	fprintf(stderr, "%s: Failed to open control device: %s\n", kProgramName,
		strerror(errno));
	exit(1);
}


status_t
install_file(const char *file, bool readOnly, const uint8* key,
	uint32 keyLength, bool initialize = false)
{
	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open control device: %s\n", kProgramName,
			strerror(errno));
		return errno;
	}

	char password[256];
	if (key == NULL) {
		// turn off Terminal echo
		struct termios termios;
		tcgetattr(STDOUT_FILENO, &termios);
		termios.c_lflag &= ~(ECHO | ECHONL);
		tcsetattr(STDOUT_FILENO, TCSANOW, &termios);

		while (true) {
			printf("Please enter a password: ");
			fflush(stdout);
			fgets(password, sizeof(password), stdin);
		
			char retype[256];
			printf("\nPlease reenter: ");
			fflush(stdout);
			fgets(retype, sizeof(retype), stdin);

			putchar('\n');

			if (!strcmp(password, retype))
				break;

			printf("\nPasswords do not match, try again!\n");
		}

		// turn on Terminal echo
		termios.c_lflag |= ECHO;
		tcsetattr(STDOUT_FILENO, TCSANOW, &termios);

		key = (uint8*)password;
		keyLength = strlen(password) - 1;
	}

	// set up the info
	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);
	info.key = key;
	info.key_length = keyLength;
	info.random_data = NULL;
	info.random_length = 0;
	info.read_only = readOnly;

	strcpy(info.file_name, file);

	uint8 random[2048];
	if (initialize) {
		// generate random data to be used as salt and AES keys
		fill_random_buffer(random, sizeof(random));
		info.random_data = random;
		info.random_length = sizeof(random);
	}

	// issue the ioctl
	status_t error = B_OK;
	if (ioctl(fd, initialize
			? ENCRYPTED_DRIVE_INITIALIZE_FILE : ENCRYPTED_DRIVE_REGISTER_FILE,
			&info) != 0) {
		error = errno;
		fprintf(stderr, "%s: Failed to install device: %s\n", kProgramName,
			strerror(error));
	} else {
		printf("File \"%s\" registered as device \"%s\".\n", file,
			info.device_name);
	}
	// close the control device
	close(fd);
	return error;
}


status_t
uninstall_file(const char *device)
{
	// open the device
	int fd = open(device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open device \"%s\": %s\n", kProgramName,
			device, strerror(errno));
		return errno;
	}

	// issue the ioctl
	status_t error = B_OK;
	if (ioctl(fd, ENCRYPTED_DRIVE_UNREGISTER_FILE, NULL) != 0) {
		error = errno;
		fprintf(stderr, "%s: Failed to uninstall device: %s\n", kProgramName,
			strerror(error));
	}
	// close the control device
	close(fd);
	return error;
}


void
list_devices()
{
	printf("%-34s  %s\n--\n", "Device", "Uses");

	for (int32 i = 0; i < 10; i++) {
		char path[B_PATH_NAME_LENGTH];
		snprintf(path, B_PATH_NAME_LENGTH, "%s/%ld/raw",
			ENCRYPTED_DRIVE_DIRECTORY, i);

		// open the device
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		// set up the info
		encrypted_drive_info info;
		info.magic = ENCRYPTED_DRIVE_MAGIC;
		info.drive_info_size = sizeof(info);

		// issue the ioctl
		status_t error = B_OK;
		if (ioctl(fd, ENCRYPTED_DRIVE_GET_INFO, &info) == 0) {
			printf("%-34s  %s%s%s\n", info.device_name, info.file_name,
				info.hidden ? " (hidden)" : "",
				info.read_only ? " (read-only)" : "");
		}

		close(fd);
	}
}


int
main(int argc, const char **argv)
{
	status_t error = B_OK;
	int argIndex = 1;
	enum { INSTALL, UNINSTALL, INITIALIZE, LIST } mode = INSTALL;
	const uint8* key = NULL;
	uint32 keyLength = 0;
	bool readOnly = false;

	// parse options
	for (; error == B_OK && argIndex < argc
		   && argv[argIndex][0] == '-'; argIndex++) {
		const char *arg = argv[argIndex];
		if (arg[1] == '-') {
			// "--" option
			arg += 2;
			if (!strcmp(arg, "install") || !strcmp(arg, "add")) {
				mode = INSTALL;
			} else if (!strcmp(arg, "uninstall") || !strcmp(arg, "remove")
				|| !strcmp(arg, "delete")) {
				mode = UNINSTALL;
			} else if (!strcmp(arg, "initialize") || !strcmp(arg, "init")) {
				mode = INITIALIZE;
			} else if (!strcmp(arg, "list")) {
				mode = LIST;
			} else if (!strcmp(arg, "read-only")) {
				readOnly = true;
			} else if (!strcmp(arg, "help")) {
				print_usage();
				return 0;
			} else if (!strcmp(arg, "key")) {
				if (argIndex + 1 >= argc) {
					print_usage(true);
					return 1;
				}
				key = (uint8*)argv[argIndex + 1];
				keyLength = strlen((char*)key);
				argIndex++;
			} else {
				fprintf(stderr, "%s: Invalid option \"-%s\".\n", kProgramName,
					arg);
				print_usage(true);
				return 1;
			}
		} else {
			// "-" options
			arg++;
			int32 count = strlen(arg);
			for (int i = 0; error == B_OK && i < count; i++) {
				switch (arg[i]) {
					case 'h':
						print_usage();
						return 0;
					default:
						fprintf(stderr, "%s: Invalid option \"-%c\".\n",
							kProgramName, arg[i]);
						print_usage(true);
						return 1;
				}
			}
		}
	}

	// parse rest (the file name)
	if (argIndex != argc - 1 && mode != LIST) {
		print_usage(true);
		return 1;
	}
	const char* file = argv[argIndex];

	test_for_driver();

	// do the job
	switch (mode) {
		case INSTALL:
			error = install_file(file, readOnly, key, keyLength);
			break;
		case UNINSTALL:
			error = uninstall_file(file);
			break;
		case INITIALIZE:
			error = install_file(file, false, key, keyLength, true);
			break;
		case LIST:
			list_devices();
			error = B_OK;
			break;
	}

	return error == B_OK ? 0 : 1;
}

