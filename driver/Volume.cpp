/*
 * Copyright 2008-2025, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "Volume.h"

#include <ByteOrder.h>
#include <Drivers.h>
#include <KernelExport.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "crypt.h"
#include "crc32.h"


#ifndef DPRINTF
#	ifdef USER_MODE
#		define DPRINTF(...) printf(__VA_ARGS__)
#	else
#		define DPRINTF(...) dprintf(__VA_ARGS__)
#	endif
#endif

#define TRACE_VOLUME
#ifdef TRACE_VOLUME
#	define TRACE(...)	DPRINTF(__VA_ARGS__)
#else
#	define TRACE(...)	;
#endif


const uint32 kTrueCryptMagic = 'TRUE';

#define DISK_KEY_SIZE				64
#define HIDDEN_HEADER_OFFSET		1536
#define RIPEMD160_ITERATIONS		2000
#define BYTES_PER_XTS_BLOCK			16
#define BLOCKS_PER_XTS_DATA_UNIT	(BLOCK_SIZE / BYTES_PER_XTS_BLOCK)

struct true_crypt_header {
	uint32	magic;
	uint16	version;
	uint16	required_program_version;
	uint32	crc_checksum;
	uint8	_reserved1[16];
	uint64	hidden_size;
	// v4 fields
	uint64	volume_size;
	uint64	encrypted_offset;
	uint64	encrypted_size;
	uint32	flags;
	// v5
	uint32	block_size;

	uint8	_reserved2[120];
	uint32	header_crc_checksum;
	uint8	disk_key[256];

	uint32 Magic() const
		{ return B_BENDIAN_TO_HOST_INT32(magic); }
	uint16 Version() const
		{ return B_BENDIAN_TO_HOST_INT16(version); }
	uint16 RequiredProgramVersion() const
		{ return B_BENDIAN_TO_HOST_INT16(required_program_version); }
	uint32 CrcChecksum() const
		{ return B_BENDIAN_TO_HOST_INT32(crc_checksum); }
	uint32 HeaderCrcChecksum() const
		{ return B_BENDIAN_TO_HOST_INT32(header_crc_checksum); }
	uint64 HiddenSize() const
		{ return B_BENDIAN_TO_HOST_INT64(hidden_size); }
	uint64 VolumeSize() const
		{ return B_BENDIAN_TO_HOST_INT64(volume_size); }
	uint64 EncryptedOffset() const
		{ return B_BENDIAN_TO_HOST_INT64(encrypted_offset); }
	uint64 EncryptedSize() const
		{ return B_BENDIAN_TO_HOST_INT64(encrypted_size); }
	uint32 Flags() const
		{ return B_BENDIAN_TO_HOST_INT32(flags); }
	uint32 BlockSize() const
		{ return B_BENDIAN_TO_HOST_INT32(block_size); }
} _PACKED;



static void
dump_true_crypt_header(true_crypt_header& header)
{
	DPRINTF("magic: %.4s\n", (char*)&header.magic);
	DPRINTF("version: %x\n", header.Version());
	DPRINTF("required program version: %x\n", header.RequiredProgramVersion());
	DPRINTF("crc checksum: %lu (%lu)\n", header.CrcChecksum(),
		crc32(header.disk_key, 256));
	DPRINTF("hidden size: %lld\n", header.HiddenSize());

	if (header.Version() >= 4) {
		DPRINTF("volume size: %lld\n", header.VolumeSize());
		DPRINTF("encrypted offset: %lld\n", header.EncryptedOffset());
		DPRINTF("encrypted size: %lld\n", header.EncryptedSize());
		DPRINTF("flags: %lx\n", header.Flags());
		DPRINTF("header crc checksum: %lx\n", header.HeaderCrcChecksum());
	}
	if (header.Version() >= 5)
		DPRINTF("block size: %lx\n", header.BlockSize());
}


static bool
valid_true_crypt_header(true_crypt_header& header)
{
	if (header.Magic() != kTrueCryptMagic)
		return false;
	if (header.CrcChecksum() != crc32(header.disk_key, 256))
		return false;

	if (header.Version() >= 0x4
		&& header.HeaderCrcChecksum() != crc32((uint8*)&header, 188))
		return false;

	return true;
}


static status_t
get_size(int fd, off_t& size)
{
	struct stat stat;
	if (fstat(fd, &stat) < 0)
		return errno;

	if (S_ISBLK(stat.st_mode) || S_ISCHR(stat.st_mode)) {
		device_geometry geometry;
		if (ioctl(fd, B_GET_GEOMETRY, &geometry) < 0)
			return errno;

		size = 1LL * geometry.head_count * geometry.cylinder_count
			* geometry.sectors_per_track * geometry.bytes_per_sector;
		if (size < 0)
			size = 0;
	} else
		size = stat.st_size;

	return B_OK;
}


//	#pragma mark -


Volume::Volume(CryptContext& context)
	:
	fContext(context)
{
}


Volume::~Volume()
{
}


status_t
Volume::Detect(int fd, const uint8* key, uint32 keyLength)
{
	off_t headerOffset;
	uint8 buffer[BLOCK_SIZE];
	true_crypt_header header;
	return _Detect(fd, key, keyLength, headerOffset, buffer, header);
}


status_t
Volume::Setup(int fd, const uint8* key, uint32 keyLength, const uint8* random, uint32 randomLength)
{
	off_t size;
	status_t status = get_size(fd, size);
	if (status != B_OK)
		return status;

	fOffset = max_c(4096, BLOCK_SIZE);
	fSize = size - fOffset;
	fHidden = false;

	const uint8* salt = random;
	random += PKCS5_SALT_SIZE;

	uint8 buffer[BLOCK_SIZE];
	memcpy(buffer, salt, PKCS5_SALT_SIZE);
	memset(buffer + PKCS5_SALT_SIZE, 0, BLOCK_SIZE - PKCS5_SALT_SIZE);

	true_crypt_header& header = *(true_crypt_header*)&buffer[PKCS5_SALT_SIZE];
	header.magic = B_HOST_TO_BENDIAN_INT32(kTrueCryptMagic);
	header.version = B_HOST_TO_BENDIAN_INT16(0x4);
	header.required_program_version = B_HOST_TO_BENDIAN_INT16(0x600);
	header.volume_size = B_HOST_TO_BENDIAN_INT64(fSize);
	header.encrypted_offset = B_HOST_TO_BENDIAN_INT64(fOffset);
	header.encrypted_size = B_HOST_TO_BENDIAN_INT64(fSize);
	header.flags = 0;
	memcpy(header.disk_key, random, sizeof(header.disk_key));
	header.crc_checksum = B_HOST_TO_BENDIAN_INT32(crc32(header.disk_key, 256));
	header.header_crc_checksum
		= B_HOST_TO_BENDIAN_INT32(crc32((uint8*)&header, 188));

	return _WriteHeader(fd, key, keyLength, 0, buffer);
}


status_t
Volume::SetPassword(int fd, const uint8* oldKey, uint32 oldKeyLength, const uint8* newKey,
	uint32 newKeyLength)
{
	off_t headerOffset;
	uint8 buffer[BLOCK_SIZE];
	true_crypt_header header;
	status_t status = _Detect(fd, oldKey, oldKeyLength, headerOffset, buffer,
		header);
	if (status != B_OK)
		return status;

//	header.required_program_version = B_HOST_TO_BENDIAN_INT16(0x800);
	header.volume_size = B_HOST_TO_BENDIAN_INT64(fSize);
	header.crc_checksum = B_HOST_TO_BENDIAN_INT32(crc32(header.disk_key, 256));
	header.header_crc_checksum
		= B_HOST_TO_BENDIAN_INT32(crc32((uint8*)&header, 188));
	memcpy(buffer + PKCS5_SALT_SIZE, &header, sizeof(true_crypt_header));

DPRINTF("HEADER OFFSET: %Ld\n", headerOffset);
DPRINTF("NEW KEY: %s\n", newKey);
	return _WriteHeader(fd, newKey, newKeyLength, headerOffset, buffer);
}


status_t
Volume::Resize(int fd, const uint8* key, uint32 keyLength, off_t newSize)
{
	off_t headerOffset;
	uint8 buffer[BLOCK_SIZE];
	true_crypt_header header;
	status_t status = _Detect(fd, key, keyLength, headerOffset, buffer, header);
	if (status != B_OK)
		return status;

	if (fSize == newSize)
		return B_OK;

	fSize = newSize;

	header.volume_size = B_HOST_TO_BENDIAN_INT64(fSize);
	header.encrypted_size = B_HOST_TO_BENDIAN_INT64(fSize);
	header.crc_checksum = B_HOST_TO_BENDIAN_INT32(crc32(header.disk_key, 256));
	header.header_crc_checksum
		= B_HOST_TO_BENDIAN_INT32(crc32((uint8*)&header, 188));
	memcpy(buffer + PKCS5_SALT_SIZE, &header, sizeof(true_crypt_header));

	return _WriteHeader(fd, key, keyLength, headerOffset, buffer);
}


status_t
Volume::_Detect(int fd, const uint8* key, uint32 keyLength, off_t& offset, uint8* buffer,
	true_crypt_header& header)
{
	off_t size;
	status_t status = get_size(fd, size);
	if (status != B_OK)
		return status;

	offset = 0;
	if (_Detect(fd, offset, size, key, keyLength, buffer, header) == B_OK)
		return B_OK;

	offset = size - HIDDEN_HEADER_OFFSET;
	return _Detect(fd, offset, size, key, keyLength, buffer, header);
}


status_t
Volume::_Detect(int fd, off_t offset, off_t size, const uint8* key, uint32 keyLength,
	uint8* buffer, true_crypt_header& header)
{
	ssize_t bytesRead = read_pos(fd, offset, buffer, BLOCK_SIZE);
	if (bytesRead != BLOCK_SIZE)
		return bytesRead < 0 ? errno : B_IO_ERROR;

	// decrypt header first

	uint8* encryptedHeader = buffer + PKCS5_SALT_SIZE;
	uint8* salt = buffer;
	uint8 diskKey[DISK_KEY_SIZE];

	derive_key(key, keyLength, salt, PKCS5_SALT_SIZE, diskKey, DISK_KEY_SIZE);
//dprintf("salt %x, key %x\n", *(int*)salt, *(int*)diskKey);

	status_t status = fContext.Init(ALGORITHM_AES, MODE_XTS, diskKey, DISK_KEY_SIZE);
	if (status != B_OK)
		return status;

	memcpy(&header, encryptedHeader, sizeof(true_crypt_header));

	fContext.Decrypt((uint8*)&header, sizeof(true_crypt_header));

	if (!valid_true_crypt_header(header)) {
		dump_true_crypt_header(header);

		// Try with legacy encryption mode LRW instead
		status = fContext.Init(ALGORITHM_AES, MODE_LRW, diskKey, DISK_KEY_SIZE);
		if (status != B_OK)
			return status;

		memcpy(&header, encryptedHeader, sizeof(true_crypt_header));

		fContext.Decrypt((uint8*)&header, sizeof(true_crypt_header));

		if (!valid_true_crypt_header(header)) {
			dump_true_crypt_header(header);
			return B_PERMISSION_DENIED;
		}
	}

	if (header.RequiredProgramVersion() >= 0x700) {
		// TODO: test if the block size is really not 512 bytes
		DPRINTF("header version not yet supported!\n");
		return B_NOT_SUPPORTED;
	}

	// then init context with the keys from the unencrypted header

	fContext.SetKey(header.disk_key, sizeof(header.disk_key));

	if (offset != 0) {
		// this is a hidden drive, take over the size from the header
		fSize = B_BENDIAN_TO_HOST_INT64(header.hidden_size);
		fOffset = offset - fSize;
		fHidden = true;
	} else {
		fOffset = BLOCK_SIZE;
		fSize = size - BLOCK_SIZE;
		fHidden = false;
	}
	if (header.Version() >= 4) {
		fOffset = header.EncryptedOffset();
		fSize = header.EncryptedSize();
	}

	fContext.SetBlockOffset(fOffset / BLOCK_SIZE);
	return B_OK;
}


//! Use key + salt to encrypt the header, and write it to disk.
status_t
Volume::_WriteHeader(int fd, const uint8* key, uint32 keyLength, off_t headerOffset, uint8* buffer)
{
	uint8 diskKey[DISK_KEY_SIZE];
	derive_key(key, keyLength, buffer, PKCS5_SALT_SIZE, diskKey, DISK_KEY_SIZE);

	status_t status = fContext.Init(ALGORITHM_AES, MODE_XTS, diskKey, DISK_KEY_SIZE);
	if (status != B_OK)
		return status;

	true_crypt_header& header = *(true_crypt_header*)&buffer[PKCS5_SALT_SIZE];
	fContext.Encrypt((uint8*)&header, BLOCK_SIZE - PKCS5_SALT_SIZE);

	ssize_t bytesWritten = write_pos(fd, headerOffset, buffer, BLOCK_SIZE);
	if (bytesWritten < 0)
		return errno;

	// use the decrypted header to init the volume encryption

	fContext.Decrypt((uint8*)&header, BLOCK_SIZE - PKCS5_SALT_SIZE);
	fContext.SetKey(header.disk_key, sizeof(header.disk_key));

	return B_OK;
}
