/*
 * Distributed under the terms of the MIT License.
 *
 * Authors:
 *		Marcus Overhagen <Marcus@Overhagen.de>
 *		Ingo Weinhold <bonefish@users.sf.net>
 *		Axel Dörfler <axeld@pinc-software.de>
 */


#include "encrypted_drive.h"

#include "encrypted_drive_icon.h"
#include "crypt.h"

#include <util/AutoLock.h>

#include <fcntl.h>
#include <errno.h>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//#define TRACE_DRIVER
#ifdef TRACE_DRIVER
#	define TRACE(x) dprintf x
#else
#	define TRACE(x) ;
#endif


static int dev_index_for_path(const char *path);

static const char *sDeviceName[] = {
	ENCRYPTED_DRIVE_DIRECTORY_REL "/0/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/1/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/2/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/3/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/4/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/5/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/6/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/7/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/8/raw",
	ENCRYPTED_DRIVE_DIRECTORY_REL "/9/raw",
	ENCRYPTED_DRIVE_CONTROL_DEVICE_REL,
	NULL
};

int32 api_version = B_CUR_DRIVER_API_VERSION;
extern device_hooks sDeviceHooks;

static struct benaphore {
	sem_id		sem;
	vint32		count;
	thread_id	owner;
	int32		nesting;
} sDriverLock;

typedef struct device_info {
	int32				open_count;
	int					fd;
	VolumeCryptContext	context;
	bool				unused;
	bool				registered;
	char				file[B_PATH_NAME_LENGTH];
	const char*			device_path;
	device_geometry		geometry;
	mutex				lock;
} device_info;

struct open_cookie {
	int32				device_index;
	uint8				buffer[65536];
};

#define kDeviceCount		11
#define kDataDeviceCount	(kDeviceCount - 1)
#define kControlDevice		(kDeviceCount - 1)

struct device_info gDeviceInfos[kDeviceCount];

static int32 gRegistrationCount = 0;
static int gControlDeviceFD = -1;
static Worker sWorker;
static recursive_lock sLock;


static inline bool
is_valid_device_index(int32 index)
{
	return index >= 0 && index < kDeviceCount;
}


static inline bool
is_valid_data_device_index(int32 index)
{
	return is_valid_device_index(index) && index != kControlDevice;
}


static int
dev_index_for_path(const char *path)
{
	int i;
	for (i = 0; i < kDeviceCount; i++) {
		if (!strcmp(path, gDeviceInfos[i].device_path))
			return i;
	}
	return -1;
}


static void
clear_device_info(int32 index)
{
	TRACE(("encrypted_drive: clear_device_info(%ld)\n", index));

	device_info& info = gDeviceInfos[index];
	info.open_count = 0;
	info.fd = -1;
	info.unused = (index != kDeviceCount - 1);
	info.registered = !info.unused;
	info.file[0] = '\0';
	info.device_path = sDeviceName[index];
	info.geometry.read_only = true;
}


static status_t
init_device_info(int32 index, encrypted_drive_info *initInfo, bool initialize)
{
	TRACE(("encrypted_drive: init_device_info(%ld)\n", index));

	if (!is_valid_data_device_index(index) || !initInfo)
		return B_BAD_VALUE;

	device_info &info = gDeviceInfos[index];
	if (!info.unused)
		return B_BAD_VALUE;

	bool readOnly = initInfo->read_only;
	mode_t mode = O_NOCACHE | (readOnly ? O_RDONLY : O_RDWR);

	// open the file
	int fd = open(initInfo->file_name, mode);
	if (fd < 0 && !readOnly) {
		// try again with read-only
		initInfo->read_only = true;
		readOnly = true;
		mode = O_RDONLY | O_NOCACHE;
		fd = open(initInfo->file_name, mode);
	}
	if (fd < 0)
		return errno;

	status_t error;
	if (initialize) {
		error = info.context.Setup(fd, initInfo->key,
			initInfo->key_length, initInfo->random_data,
			initInfo->random_length);
	} else {
		error = info.context.Detect(fd, initInfo->key,
			initInfo->key_length);
	}

	if (error == B_OK) {
		// fill in the geometry

		// default to 512 bytes block size
		uint32 blockSize = 512;
		// Optimally we have only 1 block per sector and only one head.
		// Since we have only a uint32 for the cylinder count, this won't work
		// for files > 2TB. So, we set the head count to the minimally possible
		// value.
		off_t blocks = info.context.Size() / blockSize;
		uint32 heads = (blocks + ULONG_MAX - 1) / ULONG_MAX;
		if (heads == 0)
			heads = 1;
		info.geometry.bytes_per_sector = blockSize;
	    info.geometry.sectors_per_track = 1;
	    info.geometry.cylinder_count = blocks / heads;
	    info.geometry.head_count = heads;
	    info.geometry.device_type = B_DISK;	// TODO: Add a new constant.
	    info.geometry.removable = false;
	    info.geometry.read_only = readOnly;
	    info.geometry.write_once = false;
	}

	struct stat stat;
	if (fstat(fd, &stat) < 0)
		error = errno;

	if (error == B_OK && S_ISREG(stat.st_mode)) {
		// Disable caching for underlying file! (else this driver will deadlock)
		// We probably cannot resize the file once the cache has been disabled!
	}

	if (error < B_OK) {
		// cleanup on error
		close(fd);
		if (info.open_count == 0)
			clear_device_info(index);
		return error;
	}

	// fill in the rest of the device_info structure

	info.fd = fd;
	info.unused = false;
	info.registered = true;
	strcpy(info.file, initInfo->file_name);
	info.device_path = sDeviceName[index];
	mutex_init(&info.lock, "encrypted device");

	// open_count doesn't have to be changed here
	// (encrypted_drive_open() will do that for us)

	return B_OK;
}


static status_t
uninit_device_info(int32 index)
{
	TRACE(("encrypted_drive: uninit_device_info(%ld)\n", index));

	if (!is_valid_data_device_index(index))
		return B_BAD_VALUE;

	device_info &info = gDeviceInfos[index];
	if (info.unused)
		return B_BAD_VALUE;

	close(info.fd);
	mutex_destroy(&info.lock);
	clear_device_info(index);
	return B_OK;
}


static status_t
encrypt_buffer(encrypted_drive_info& info)
{
	if (info.key == NULL || info.random_data == NULL || info.buffer == NULL
		|| info.key_length == 0 || info.random_length < PKCS5_SALT_SIZE
		|| info.buffer_length == 0)
		return B_BAD_VALUE;

	uint8 diskKey[256];
	derive_key(info.key, info.key_length, info.random_data, PKCS5_SALT_SIZE,
		diskKey, sizeof(diskKey));

	CryptContext context;
	status_t status = context.Init(ALGORITHM_AES, MODE_XTS,
		diskKey, sizeof(diskKey));
	if (status != B_OK)
		return status;

	context.Encrypt(info.buffer, info.buffer_length);
	return B_OK;
}


static status_t
decrypt_buffer(encrypted_drive_info& info)
{
	if (info.key == NULL || info.random_data == NULL || info.buffer == NULL
		|| info.key_length == 0 || info.random_length < PKCS5_SALT_SIZE
		|| info.buffer_length == 0)
		return B_BAD_VALUE;

	uint8 diskKey[256];
	derive_key(info.key, info.key_length, info.random_data, PKCS5_SALT_SIZE,
		diskKey, sizeof(diskKey));

	CryptContext context;
	status_t status = context.Init(ALGORITHM_AES, MODE_XTS,
		diskKey, sizeof(diskKey));
	if (status != B_OK)
		return status;

	context.Decrypt(info.buffer, info.buffer_length);
	return B_OK;
}


//	#pragma mark - public driver API


status_t
init_hardware(void)
{
	TRACE(("encrypted_drive: init_hardware\n"));
	return B_OK;
}


status_t
init_driver(void)
{
	TRACE(("encrypted_drive: init\n"));

	recursive_lock_init(&sLock, "encrypted_drive lock");

	new(&sWorker) Worker();
	sWorker.Init();
	init_crypt();

	// init the device infos
	for (int32 i = 0; i < kDeviceCount; i++) {
		new(&gDeviceInfos[i].context) VolumeCryptContext();
		clear_device_info(i);
	}

	return B_OK;
}


void
uninit_driver(void)
{
	TRACE(("encrypted_drive: uninit\n"));

	// uninit the device infos
	for (int32 i = 0; i < kDeviceCount; i++) {
		gDeviceInfos[i].context.~VolumeCryptContext();
	}

	uninit_crypt();
	sWorker.~Worker();

	recursive_lock_destroy(&sLock);
}


const char **
publish_devices(void)
{
	TRACE(("encrypted_drive: publish_devices\n"));
	return sDeviceName;
}


device_hooks *
find_device(const char* name)
{
	TRACE(("encrypted_drive: find_device(%s)\n", name));
	return &sDeviceHooks;
}


//	#pragma mark - device hooks


static status_t
encrypted_drive_open(const char* name, uint32 flags, void** _cookie)
{
	TRACE(("encrypted_drive: open %s\n", name));

	RecursiveLocker locker(sLock);

	int32 deviceIndex = dev_index_for_path(name);
	open_cookie* cookie;

	TRACE(("encrypted_drive: deviceIndex %ld!\n", deviceIndex));

	if (!is_valid_device_index(deviceIndex)) {
		TRACE(("encrypted_drive: wrong index!\n"));
		return B_BAD_VALUE;
	}

	if (gDeviceInfos[deviceIndex].unused) {
		TRACE(("encrypted_drive: device is unused!\n"));
		return B_NO_INIT;
	}

	if (!gDeviceInfos[deviceIndex].registered) {
		TRACE(("encrypted_drive: device has been unregistered!\n"));
		return B_NOT_ALLOWED;
	}

	cookie = new(std::nothrow) open_cookie();
	if (cookie == NULL)
		return B_NO_MEMORY;

	cookie->device_index = deviceIndex;
	*_cookie = cookie;

	if (deviceIndex != kControlDevice)
		gDeviceInfos[deviceIndex].open_count++;

	return B_OK;
}


static status_t
encrypted_drive_close(void* _cookie)
{
	open_cookie* cookie = (open_cookie*)_cookie;
	int32 deviceIndex = cookie->device_index;

	TRACE(("encrypted_drive: close() deviceIndex = %ld\n", deviceIndex));
	if (!is_valid_data_device_index(deviceIndex))
		return B_OK;

	RecursiveLocker locker(sLock);

	gDeviceInfos[deviceIndex].open_count--;
	if (gDeviceInfos[deviceIndex].open_count == 0
		&& !gDeviceInfos[deviceIndex].registered) {
		// The last FD is closed and the device has been unregistered.
		// Free its info.
		uninit_device_info(deviceIndex);
	}

	return B_OK;
}


static status_t
encrypted_drive_free(void* _cookie)
{
	TRACE(("encrypted_drive: free cookie()\n"));
	delete (open_cookie*)_cookie;
	return B_OK;
}


static status_t
encrypted_drive_read(void* _cookie, off_t position, void* buffer,
	size_t* numBytes)
{
	TRACE(("encrypted_drive: read pos = 0x%08Lx, bytes = 0x%08lx\n", position,
		*numBytes));

	// check parameters
	open_cookie* cookie = (open_cookie*)_cookie;
	int32 deviceIndex = cookie->device_index;
	if (deviceIndex == kControlDevice) {
		TRACE(("encrypted_drive: reading from control device not allowed\n"));
		return B_NOT_ALLOWED;
	}
	if (position < 0)
		return B_BAD_VALUE;

	device_info& info = gDeviceInfos[deviceIndex];
	MutexLocker locker(info.lock);

	// adjust position and numBytes according to the file size
	if (position > info.context.Size())
		position = info.context.Size();
	if (position + *numBytes > info.context.Size())
		*numBytes = info.context.Size() - position;

	if (position % info.geometry.bytes_per_sector != 0) {
		// We use the block number as part of the decryption mechanism,
		// so we have to make sure any access is block aligned.
		dprintf("TODO read partial!\n");
		return B_NOT_SUPPORTED;
	}

	position += info.context.Offset();

	status_t error = B_OK;
	size_t bytesLeft = *numBytes;
	while (bytesLeft > 0) {
		size_t bytes = min_c(bytesLeft, sizeof(cookie->buffer));

		ssize_t bytesRead = read_pos(info.fd, position, cookie->buffer,
			bytes);
		if (bytesRead < 0) {
			error = errno;
			break;
		}

		DecryptTask task(info.context, cookie->buffer, bytesRead,
			position / BLOCK_SIZE);
		TRACE(("decrypt %d: %p, %" B_PRIuSIZE ", index %" B_PRIu64 "\n",
				find_thread(NULL), cookie->buffer, bytesRead,
				position / BLOCK_SIZE));
		sWorker.AddTask(task);
		sWorker.WaitFor(task);

		if (user_memcpy(buffer, cookie->buffer, bytesRead) != B_OK) {
			error = B_BAD_ADDRESS;
			break;
		}

		buffer = (void*)((uint8*)buffer + bytesRead);
		bytesLeft -= bytesRead;
		position += bytesRead;
	}

	if (bytesLeft > 0)
		*numBytes -= bytesLeft;

	return error;
}


static status_t
encrypted_drive_write(void* _cookie, off_t position, const void* buffer,
	size_t* numBytes)
{
	TRACE(("encrypted_drive: write pos = 0x%08Lx, bytes = 0x%08lx\n", position, *numBytes));

	// check parameters
	open_cookie* cookie = (open_cookie*)_cookie;
	int32 deviceIndex = cookie->device_index;
	if (deviceIndex == kControlDevice) {
		TRACE(("encrypted_drive: writing to control device not allowed\n"));
		return B_NOT_ALLOWED;
	}
	if (position < 0)
		return B_BAD_VALUE;

	device_info &info = gDeviceInfos[deviceIndex];
	MutexLocker locker(info.lock);

	if (info.geometry.read_only)
		return B_READ_ONLY_DEVICE;

	if (position % info.geometry.bytes_per_sector != 0) {
		// We use the block number as part of the decryption mechanism,
		// so we have to make sure any access is block aligned.
		dprintf("TODO write partial!\n");
		return B_NOT_SUPPORTED;
	}

	// adjust position and numBytes according to the file size
	if (position > info.context.Size())
		position = info.context.Size();
	if (position + *numBytes > info.context.Size())
		*numBytes = info.context.Size() - position;

	position += info.context.Offset();

	size_t bytesLeft = *numBytes;
	status_t error = B_OK;
	while (bytesLeft > 0) {
		size_t bytes = min_c(bytesLeft, sizeof(cookie->buffer));
		if (user_memcpy(cookie->buffer, buffer, bytes) != B_OK) {
			error = B_BAD_ADDRESS;
			break;
		}

		EncryptTask task(info.context, cookie->buffer, bytes,
			position / BLOCK_SIZE);
		TRACE(("encrypt %d: %p, %" B_PRIuSIZE ", index %" B_PRIu64 "\n",
				find_thread(NULL), cookie->buffer, bytes,
				position / BLOCK_SIZE));
		sWorker.AddTask(task);
		sWorker.WaitFor(task);

		ssize_t bytesWritten = write_pos(info.fd, position, cookie->buffer,
			bytes);
		if (bytesWritten < 0) {
			error = errno;
			break;
		}

		buffer = (const void*)((const uint8*)buffer + bytes);
		bytesLeft -= bytes;
		position += bytes;
	}

	if (bytesLeft > 0)
		*numBytes -= bytesLeft;

	return error;
}


static status_t
encrypted_drive_control(void* _cookie, uint32 op, void* arg, size_t length)
{
	TRACE(("encrypted_drive: ioctl\n"));

	open_cookie* cookie = (open_cookie*)_cookie;
	int32 deviceIndex = cookie->device_index;
	device_info& info = gDeviceInfos[deviceIndex];

	if (deviceIndex == kControlDevice || info.unused) {
		// control device or unused data device
		switch (op) {
			case B_GET_DEVICE_SIZE:
			case B_SET_NONBLOCKING_IO:
			case B_SET_BLOCKING_IO:
			case B_GET_READ_STATUS:
			case B_GET_WRITE_STATUS:
			case B_GET_ICON:
			case B_GET_GEOMETRY:
			case B_GET_BIOS_GEOMETRY:
			case B_GET_MEDIA_STATUS:
			case B_SET_UNINTERRUPTABLE_IO:
			case B_SET_INTERRUPTABLE_IO:
			case B_FLUSH_DRIVE_CACHE:
			case B_GET_BIOS_DRIVE_ID:
			case B_GET_DRIVER_FOR_DEVICE:
			case B_SET_DEVICE_SIZE:
			case B_SET_PARTITION:
			case B_FORMAT_DEVICE:
			case B_EJECT_DEVICE:
			case B_LOAD_MEDIA:
			case B_GET_NEXT_OPEN_DEVICE:
				TRACE(("encrypted_drive: another ioctl: %lx (%lu)\n", op, op));
				return B_BAD_VALUE;

			case ENCRYPTED_DRIVE_REGISTER_FILE:
			case ENCRYPTED_DRIVE_INITIALIZE_FILE:
			{
				TRACE(("encrypted_drive: ENCRYPTED_DRIVE_REGISTER_FILE\n"));

				encrypted_drive_info *driveInfo = (encrypted_drive_info *)arg;
				if (deviceIndex != kControlDevice || driveInfo == NULL
					|| driveInfo->magic != ENCRYPTED_DRIVE_MAGIC
					|| driveInfo->drive_info_size != sizeof(encrypted_drive_info)
					|| driveInfo->key_length > 0 && driveInfo->key == NULL)
					return B_BAD_VALUE;

				status_t error = B_ERROR;
				int32 i;

				RecursiveLocker locker(sLock);

				// first, look if we already have opened that file and see
				// if it's available to us which happens when it has been
				// halted but is still in use by other components
				for (i = 0; i < kDataDeviceCount; i++) {
					if (!gDeviceInfos[i].unused
						&& gDeviceInfos[i].fd == -1
						&& !gDeviceInfos[i].registered
						&& !strcmp(gDeviceInfos[i].file, driveInfo->file_name)) {
						// mark device as unused, so that init_device_info() will succeed
						gDeviceInfos[i].unused = true;
						error = B_OK;
						break;
					}
				}

				if (error != B_OK) {
					// find an unused data device
					for (i = 0; i < kDataDeviceCount; i++) {
						if (gDeviceInfos[i].unused) {
							error = B_OK;
							break;
						}
					}
				}

				if (error == B_OK) {
					// we found a device slot, let's initialize it
					error = init_device_info(i, driveInfo,
						op == ENCRYPTED_DRIVE_INITIALIZE_FILE);
					if (error == B_OK) {
						// return the device path
						strcpy(driveInfo->device_name, "/dev/");
						strcat(driveInfo->device_name,
							gDeviceInfos[i].device_path);

						// on the first registration we need to open the
						// control device to stay loaded
						if (gRegistrationCount++ == 0) {
							char path[B_PATH_NAME_LENGTH];
							strcpy(path, "/dev/");
							strcat(path, info.device_path);
							gControlDeviceFD = open(path, O_RDONLY);
						}
					}
				}

				return error;
			}

			case ENCRYPTED_DRIVE_ENCRYPT_BUFFER:
			{
				encrypted_drive_info* driveInfo = (encrypted_drive_info*)arg;
				if (deviceIndex != kControlDevice || driveInfo == NULL
					|| driveInfo->magic != ENCRYPTED_DRIVE_MAGIC
					|| driveInfo->drive_info_size != sizeof(encrypted_drive_info)
					|| driveInfo->key_length > 0 && driveInfo->key == NULL)
					return B_BAD_VALUE;

				return encrypt_buffer(*driveInfo);
			}
			case ENCRYPTED_DRIVE_DECRYPT_BUFFER:
			{
				encrypted_drive_info* driveInfo = (encrypted_drive_info*)arg;
				if (deviceIndex != kControlDevice || driveInfo == NULL
					|| driveInfo->magic != ENCRYPTED_DRIVE_MAGIC
					|| driveInfo->drive_info_size != sizeof(encrypted_drive_info)
					|| driveInfo->key_length > 0 && driveInfo->key == NULL)
					return B_BAD_VALUE;

				return decrypt_buffer(*driveInfo);
			}

			case ENCRYPTED_DRIVE_UNREGISTER_FILE:
			case ENCRYPTED_DRIVE_GET_INFO:
				TRACE(("encrypted_drive: ENCRYPTED_DRIVE_UNREGISTER_FILE/"
					  "ENCRYPTED_DRIVE_GET_INFO on control device\n"));
				// these are called on used data files only!
				return B_BAD_VALUE;

			default:
				TRACE(("encrypted_drive: unknown ioctl: %lx (%lu)\n", op, op));
				return B_BAD_VALUE;
		}
	} else {
		// used data device
		switch (op) {
			case B_GET_DEVICE_SIZE:
				TRACE(("encrypted_drive: B_GET_DEVICE_SIZE\n"));
				*(size_t*)arg = info.context.Size();
				return B_OK;

			case B_SET_NONBLOCKING_IO:
				TRACE(("encrypted_drive: B_SET_NONBLOCKING_IO\n"));
				return B_OK;

			case B_SET_BLOCKING_IO:
				TRACE(("encrypted_drive: B_SET_BLOCKING_IO\n"));
				return B_OK;

			case B_GET_READ_STATUS:
				TRACE(("encrypted_drive: B_GET_READ_STATUS\n"));
				*(bool*)arg = true;
				return B_OK;

			case B_GET_WRITE_STATUS:
				TRACE(("encrypted_drive: B_GET_WRITE_STATUS\n"));
				*(bool*)arg = true;
				return B_OK;

			case B_GET_ICON:
			{
				TRACE(("encrypted_drive: B_GET_ICON\n"));
				device_icon *icon = (device_icon *)arg;

				if (icon->icon_size == kPrimaryImageWidth) {
					memcpy(icon->icon_data, kPrimaryImageBits, kPrimaryImageWidth * kPrimaryImageHeight);
				} else if (icon->icon_size == kSecondaryImageWidth) {
					memcpy(icon->icon_data, kSecondaryImageBits, kSecondaryImageWidth * kSecondaryImageHeight);
				} else
					return B_ERROR;

				return B_OK;
			}

			case B_GET_GEOMETRY:
				TRACE(("encrypted_drive: B_GET_GEOMETRY\n"));
				*(device_geometry *)arg = info.geometry;
				return B_OK;

			case B_GET_MEDIA_STATUS:
				TRACE(("encrypted_drive: B_GET_MEDIA_STATUS\n"));
				*(status_t*)arg = B_OK;
				return B_OK;

			case B_SET_UNINTERRUPTABLE_IO:
				TRACE(("encrypted_drive: B_SET_UNINTERRUPTABLE_IO\n"));
				return B_OK;

			case B_SET_INTERRUPTABLE_IO:
				TRACE(("encrypted_drive: B_SET_INTERRUPTABLE_IO\n"));
				return B_OK;

			case B_FLUSH_DRIVE_CACHE:
				TRACE(("encrypted_drive: B_FLUSH_DRIVE_CACHE\n"));
				return ioctl(info.fd, B_FLUSH_DRIVE_CACHE);

			case B_GET_DRIVER_FOR_DEVICE:
			case B_SET_DEVICE_SIZE:
			case B_SET_PARTITION:
			case B_FORMAT_DEVICE:
			case B_EJECT_DEVICE:
			case B_LOAD_MEDIA:
			case B_GET_NEXT_OPEN_DEVICE:
				TRACE(("encrypted_drive: another ioctl: %lx (%lu)\n", op, op));
				return B_BAD_VALUE;

			case ENCRYPTED_DRIVE_REGISTER_FILE:
				TRACE(("encrypted_drive: ENCRYPTED_DRIVE_REGISTER_FILE (data)\n"));
				return B_BAD_VALUE;
			case ENCRYPTED_DRIVE_UNREGISTER_FILE:
			{
				TRACE(("encrypted_drive: ENCRYPTED_DRIVE_UNREGISTER_FILE\n"));
				RecursiveLocker locker(sLock);

				bool wasRegistered = info.registered;
				info.registered = false;

				if (info.open_count == 0) {
					// The device is not used anymore, we can uninitialize
					// it now
					uninit_device_info(deviceIndex);
				}

				// on the last unregistration we need to close the
				// control device
				if (wasRegistered && --gRegistrationCount == 0) {
					close(gControlDeviceFD);
					gControlDeviceFD = -1;
				}

				return B_OK;
			}
			case ENCRYPTED_DRIVE_GET_INFO:
			{
				TRACE(("encrypted_drive: ENCRYPTED_DRIVE_GET_INFO\n"));

				encrypted_drive_info *driveInfo = (encrypted_drive_info *)arg;
				if (driveInfo == NULL
					|| driveInfo->magic != ENCRYPTED_DRIVE_MAGIC
					|| driveInfo->drive_info_size != sizeof(encrypted_drive_info))
					return B_BAD_VALUE;

				strcpy(driveInfo->file_name, info.file);
				strcpy(driveInfo->device_name, "/dev/");
				strcat(driveInfo->device_name, info.device_path);
				driveInfo->read_only = info.geometry.read_only;
				driveInfo->hidden = info.context.IsHidden();
				return B_OK;
			}

			default:
				TRACE(("encrypted_drive: unknown ioctl: %lx (%lu)\n", op, op));
				return B_BAD_VALUE;
		}
	}

}


device_hooks sDeviceHooks = {
	encrypted_drive_open,
	encrypted_drive_close,
	encrypted_drive_free,
	encrypted_drive_control,
	encrypted_drive_read,
	encrypted_drive_write
};

