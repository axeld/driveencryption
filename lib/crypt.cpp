/*
 * Copyright 2008-2013, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 *
 * The XTS/LRW modes and the RIPE160 code is distributed under the
 * Truecrypt License.
 */


#include "crypt.h"

#include "aes.h"
#include "crc32.h"
#include "gf_mul.h"
#include "ripemd160.h"

#include "Worker.h"

#include <ByteOrder.h>
#include <Drivers.h>
#include <KernelExport.h>

#include <errno.h>
#include <new>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


//#define TRACE_CRYPT
#ifdef TRACE_CRYPT
#	define TRACE(...)	dprintf(__VA_ARGS__)
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


class ThreadContext {
public:
	ThreadContext();
	ThreadContext(const ThreadContext& context);
	~ThreadContext();

	ssize_t AddBuffer(size_t size);
	void* BufferFor(int32 offset);
	void Reset();

	ThreadContext& operator=(const ThreadContext& other);

private:
	size_t _CapacityFor(size_t size);

	void*			fBuffer;
	size_t			fBufferSize;
	int32			fFirstFree;
};

class EncryptionAlgorithm {
public:
	EncryptionAlgorithm() {}
	virtual ~EncryptionAlgorithm() {}

	virtual status_t Init(ThreadContext& context) = 0;
	virtual status_t SetKey(ThreadContext& context, const uint8* key,
		size_t keyLength) = 0;
	virtual status_t SetCompleteKey(ThreadContext& context, const uint8* key,
		size_t keyLength) = 0;

	virtual EncryptionAlgorithm* Clone(ThreadContext& context) = 0;

	virtual void Decrypt(ThreadContext& context, uint8 *data,
		size_t length) = 0;
	virtual void Encrypt(ThreadContext& context, uint8 *data,
		size_t length) = 0;

	virtual void SetMode(EncryptionMode* mode) = 0;
	virtual encryption_algorithm Type() = 0;
};

class AESAlgorithm : public EncryptionAlgorithm {
public:
	AESAlgorithm();
	virtual ~AESAlgorithm();

	virtual status_t Init(ThreadContext& context);
	virtual status_t SetKey(ThreadContext& context, const uint8* key,
		size_t keyLength);
	virtual status_t SetCompleteKey(ThreadContext& context, const uint8* key,
		size_t keyLength);

	virtual EncryptionAlgorithm* Clone(ThreadContext& context);

	virtual void Decrypt(ThreadContext& context, uint8 *data,
		size_t length);
	virtual void Encrypt(ThreadContext& context, uint8 *data,
		size_t length);

	virtual void SetMode(EncryptionMode* mode);
	virtual encryption_algorithm Type() { return ALGORITHM_AES; }

private:
	int32			fEncryptScheduler;
	int32			fDecryptScheduler;
	encryption_mode	fMode;
};

class EncryptionMode {
public:
	EncryptionMode() {}
	virtual ~EncryptionMode() {}

	virtual status_t Init(ThreadContext& context,
		EncryptionAlgorithm* algorithm) = 0;
	virtual status_t SetKey(ThreadContext& context, const uint8* key,
		size_t keyLength) = 0;
	virtual status_t SetCompleteKey(ThreadContext& context, const uint8* key,
		size_t keyLength) = 0;
	virtual void SetBlockOffset(off_t offset) = 0;

	virtual void DecryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex) = 0;
	virtual void EncryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex) = 0;

	virtual void Decrypt(ThreadContext& context, uint8 *data,
		size_t length) = 0;
	virtual void Encrypt(ThreadContext& context, uint8 *data,
		size_t length) = 0;

	virtual encryption_mode Type() = 0;
};

class XTSMode : public EncryptionMode {
public:
	XTSMode();
	virtual ~XTSMode();

	virtual status_t Init(ThreadContext& context,
		EncryptionAlgorithm* algorithm);
	virtual status_t SetKey(ThreadContext& context, const uint8* key,
		size_t keyLength);
	virtual status_t SetCompleteKey(ThreadContext& context, const uint8* key,
		size_t keyLength);
	virtual void SetBlockOffset(off_t offset);

	virtual void DecryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex);
	virtual void EncryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex);

	virtual void Decrypt(ThreadContext& context, uint8 *data, size_t length);
	virtual void Encrypt(ThreadContext& context, uint8 *data, size_t length);

	virtual encryption_mode Type() { return MODE_XTS; }

protected:
	EncryptionAlgorithm*	fAlgorithm;
	EncryptionAlgorithm*	fSecondaryAlgorithm;
};

class LRWMode : public EncryptionMode {
public:
	LRWMode();
	virtual ~LRWMode();

	virtual status_t Init(ThreadContext& context,
		EncryptionAlgorithm* algorithm);
	virtual status_t SetKey(ThreadContext& context, const uint8* key,
		size_t keyLength);
	virtual status_t SetCompleteKey(ThreadContext& context, const uint8* key,
		size_t keyLength);
	virtual void SetBlockOffset(off_t offset);

	virtual void DecryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex = 0);
	virtual void EncryptBlock(ThreadContext& context, uint8 *data,
		size_t length, uint64 blockIndex = 0);

	virtual void Decrypt(ThreadContext& context, uint8 *data, size_t length);
	virtual void Encrypt(ThreadContext& context, uint8 *data, size_t length);

	virtual encryption_mode Type() { return MODE_LRW; }

protected:
	EncryptionAlgorithm*	fAlgorithm;
	int32					fGaloisField;
	off_t					fOffset;
};


class CryptJob : public Job {
public:
	CryptJob()
		:
		fTask(NULL),
		fThreadContext(NULL)
	{
	}

	void SetTo(CryptTask* task, ThreadContext* context, uint8* data,
		size_t length, uint64 blockIndex)
	{
		fTask = task;
		fThreadContext = context;
		fData = data;
		fLength = length;
		fBlockIndex = blockIndex;
	}

	void Done();

protected:
	CryptTask*		fTask;
	ThreadContext*	fThreadContext;
	uint8*			fData;
	size_t			fLength;
	uint64			fBlockIndex;
};

class DecryptJob : public CryptJob {
public:
	DecryptJob()
	{
	}

	virtual void Do()
	{
		TRACE("  %d: decrypt %p, %" B_PRIuSIZE ", index %" B_PRIu64
			", context %p\n", find_thread(NULL), fData, fLength, fBlockIndex,
			fThreadContext);
		fTask->Mode()->DecryptBlock(*fThreadContext, fData, fLength,
			fBlockIndex);
		Done();
	}
};

class EncryptJob : public CryptJob {
public:
	EncryptJob()
	{
	}

	virtual void Do()
	{
		TRACE("  %d: encrypt %p, %" B_PRIuSIZE ", index %" B_PRIu64
			", context %p\n", find_thread(NULL), fData, fLength, fBlockIndex,
			fThreadContext);
		fTask->Mode()->EncryptBlock(*fThreadContext, fData, fLength,
			fBlockIndex);
		Done();
	}
};


static int32 sThreadCount;


//	#pragma mark - RIPEMD160 key computation


void
hmac_ripemd160(const uint8 *key, int32 keyLength, const uint8 *input,
	int32 length, uint8 *digest)
{
    ripemd160_context context;
    uint8 keyInnerPad[65];  /* inner padding - key XORd with ipad */
    uint8 keyOuterPad[65];  /* outer padding - key XORd with opad */
    uint8 tk[RIPEMD160_DIGESTSIZE];
    int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = ripemd160(key), as per HMAC specifications. */
    if (keyLength > RIPEMD160_BLOCKSIZE) {
        ripemd160_context tctx;

        ripemd160_init(&tctx);
        ripemd160_update(&tctx, key, keyLength);
        ripemd160_final(tk, &tctx);

        key = tk;
        keyLength = RIPEMD160_DIGESTSIZE;

		memset(&tctx, 0, sizeof(tctx));	// Prevent leaks
    }

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


	/* start out by storing key in pads */
	memset(keyInnerPad, 0x36, sizeof(keyInnerPad));
    memset(keyOuterPad, 0x5c, sizeof(keyOuterPad));

    /* XOR key with ipad and opad values */
    for (i = 0; i < keyLength; i++) {
        keyInnerPad[i] ^= key[i];
        keyOuterPad[i] ^= key[i];
    }

    /* perform inner RIPEMD-160 */

    ripemd160_init(&context);				/* init context for 1st pass */
    ripemd160_update(&context, keyInnerPad, RIPEMD160_BLOCKSIZE);
    ripemd160_update(&context, input, length); /* then text of datagram */
    ripemd160_final(digest, &context);		/* finish up 1st pass */

    /* perform outer RIPEMD-160 */
    ripemd160_init(&context);				/* init context for 2nd pass */
    ripemd160_update(&context, keyOuterPad, RIPEMD160_BLOCKSIZE);
    /* results of 1st hash */
    ripemd160_update(&context, digest, RIPEMD160_DIGESTSIZE);
    ripemd160_final(digest, &context);		/* finish up 2nd pass */

	/* Prevent possible leaks. */
    memset(keyInnerPad, 0, sizeof(keyInnerPad));
    memset(keyOuterPad, 0, sizeof(keyOuterPad));
	memset(tk, 0, sizeof(tk));
	memset(&context, 0, sizeof(context));
}


void
derive_u_ripemd160(const uint8 *key, int keyLength, const uint8 *salt,
	int saltLength, int iterations, uint8 *u, int b)
{
	uint8 j[RIPEMD160_DIGESTSIZE], k[RIPEMD160_DIGESTSIZE];
	uint8 init[128];
	uint8 counter[4];
	int c, i;

	/* iteration 1 */
	memset(counter, 0, 4);
	counter[3] = (char) b;
	memcpy(init, salt, saltLength);	/* salt */
	memcpy(&init[saltLength], counter, 4);	/* big-endian block number */
	hmac_ripemd160(key, keyLength, init, saltLength + 4, j);
	memcpy(u, j, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++) {
		hmac_ripemd160(key, keyLength, j, RIPEMD160_DIGESTSIZE, k);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++) {
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	memset(j, 0, sizeof(j));
	memset(k, 0, sizeof(k));
}


void
derive_key_ripemd160(const uint8 *key, int keyLength, const uint8 *salt,
	int saltLength, int iterations, uint8 *diskKey, int diskKeyLength)
{
	uint8 u[RIPEMD160_DIGESTSIZE];
	int b, l, r;

	if (diskKeyLength % RIPEMD160_DIGESTSIZE)
		l = 1 + diskKeyLength / RIPEMD160_DIGESTSIZE;
	else
		l = diskKeyLength / RIPEMD160_DIGESTSIZE;

	r = diskKeyLength - (l - 1) * RIPEMD160_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++) {
		derive_u_ripemd160(key, keyLength, salt, saltLength, iterations, u, b);
		memcpy(diskKey, u, RIPEMD160_DIGESTSIZE);
		diskKey += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160(key, keyLength, salt, saltLength, iterations, u, b);
	memcpy(diskKey, u, r);

	/* Prevent possible leaks. */
	memset(u, 0, sizeof(u));
}


//	#pragma mark -


static void
xor128(uint64 *a, uint64 *b)
{
	*a++ ^= *b++;
	*a ^= *b;
}


static void
dump_true_crypt_header(true_crypt_header& header)
{
	dprintf("magic: %.4s\n", (char*)&header.magic);
	dprintf("version: %x\n", header.Version());
	dprintf("required program version: %x\n", header.RequiredProgramVersion());
	dprintf("crc checksum: %lu (%lu)\n", header.CrcChecksum(),
		crc32(header.disk_key, 256));
	dprintf("hidden size: %lld\n", header.HiddenSize());

	if (header.Version() >= 4) {
		dprintf("volume size: %lld\n", header.VolumeSize());
		dprintf("encrypted offset: %lld\n", header.EncryptedOffset());
		dprintf("encrypted size: %lld\n", header.EncryptedSize());
		dprintf("flags: %lx\n", header.Flags());
		dprintf("header crc checksum: %lx\n", header.HeaderCrcChecksum());
	}
	if (header.Version() >= 5)
		dprintf("block size: %lx\n", header.BlockSize());
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


static EncryptionAlgorithm*
create_algorithm(enum encryption_algorithm algorithm)
{
	switch (algorithm) {
		case ALGORITHM_AES:
			return new(std::nothrow) AESAlgorithm;

		default:
			return NULL;
	}
}


static EncryptionMode*
create_mode(enum encryption_mode mode)
{
	switch (mode) {
		case MODE_XTS:
			return new(std::nothrow) XTSMode;

		case MODE_LRW:
			return new(std::nothrow) LRWMode;

		default:
			return NULL;
	}
}


//	#pragma mark - ThreadContext


ThreadContext::ThreadContext()
	:
	fBuffer(NULL),
	fBufferSize(0),
	fFirstFree(0)
{
}


ThreadContext::ThreadContext(const ThreadContext& context)
{
	*this = context;
}


ThreadContext::~ThreadContext()
{
	free(fBuffer);
}


ssize_t
ThreadContext::AddBuffer(size_t size)
{
	if (size == 0)
		return B_BAD_VALUE;

	if (size < fBufferSize - fFirstFree) {
		// there is still enough space available
		int32 index = fFirstFree;
		fFirstFree += size;
		return index;
	}

	// We need to resize our buffer in order to make space

	size_t newSize = _CapacityFor(fFirstFree + size);
	void* buffer = realloc(fBuffer, newSize);
	if (buffer == NULL)
		return B_NO_MEMORY;

	fBuffer = buffer;
	fBufferSize = newSize;
	int32 index = fFirstFree;
	fFirstFree += size;

	return index;
}


void*
ThreadContext::BufferFor(int32 offset)
{
	return (void*)((uint8*)fBuffer + offset);
}


void
ThreadContext::Reset()
{
	free(fBuffer);
	fBufferSize = 0;
	fBuffer = NULL;
	fFirstFree = 0;
}


ThreadContext&
ThreadContext::operator=(const ThreadContext& other)
{
	fBuffer = malloc(other.fBufferSize);
	if (fBuffer != NULL) {
		fBufferSize = other.fBufferSize;
		fFirstFree = other.fFirstFree;
		memcpy(fBuffer, other.fBuffer, fFirstFree);
	} else {
		fBufferSize = 0;
		fFirstFree = 0;
	}

	return *this;
}


/*!	Returns the capacity for allocating a chunk of size bytes.
	In fact, this will return the closest power of two number of bytes higher
	as \a size.
*/
size_t
ThreadContext::_CapacityFor(size_t size)
{
	if (size > (1UL << 30))
		return size;

	int32 nextPowerOfTwo = 64;
	while (nextPowerOfTwo < size) {
		nextPowerOfTwo <<= 1;
	}
	return nextPowerOfTwo;
}


//	#pragma mark - CryptJob


void
CryptJob::Done()
{
	fTask->Put(fThreadContext);
	delete this;
}


//	#pragma mark - Encryption algorithms


AESAlgorithm::AESAlgorithm()
	:
	fEncryptScheduler(-1),
	fDecryptScheduler(-1)
{
}


AESAlgorithm::~AESAlgorithm()
{
}


status_t
AESAlgorithm::Init(ThreadContext& context)
{
	// Make space for our key schedule buffer
	fEncryptScheduler = context.AddBuffer(sizeof(aes_encrypt_ctx));
	fDecryptScheduler = context.AddBuffer(sizeof(aes_decrypt_ctx));
	if (fEncryptScheduler < 0 || fDecryptScheduler < 0)
		return B_NO_MEMORY;

	return B_OK;
}


status_t
AESAlgorithm::SetKey(ThreadContext& context, const uint8* key,
	size_t keyLength)
{
//dprintf("%s-aes key: %x (%lu)\n", fMode == MODE_LRW ? "lrw" : "xts", *(int*)key, keyLength);
	if (aes_encrypt_key(key, keyLength,
			(aes_encrypt_ctx*)context.BufferFor(fEncryptScheduler))
				!= EXIT_SUCCESS)
		return B_ERROR;

	if (aes_decrypt_key(key, keyLength,
			(aes_decrypt_ctx*)context.BufferFor(fDecryptScheduler))
				!= EXIT_SUCCESS)
		return B_ERROR;

	return B_OK;
}


status_t
AESAlgorithm::SetCompleteKey(ThreadContext& context, const uint8* key,
	size_t keyLength)
{
	if (fMode == MODE_LRW)
		return SetKey(context, key + KEY_SIZE, KEY_SIZE);

	return SetKey(context, key, KEY_SIZE);
}


EncryptionAlgorithm*
AESAlgorithm::Clone(ThreadContext& context)
{
	AESAlgorithm* clone = new (std::nothrow) AESAlgorithm();
	if (clone == NULL)
		return NULL;

	// Copy our schedule data
	clone->fEncryptScheduler = context.AddBuffer(sizeof(aes_encrypt_ctx));
	clone->fDecryptScheduler = context.AddBuffer(sizeof(aes_decrypt_ctx));
	if (clone->fEncryptScheduler < 0 || clone->fDecryptScheduler < 0) {
		delete clone;
		return NULL;
	}

	memcpy(context.BufferFor(clone->fEncryptScheduler),
		context.BufferFor(fEncryptScheduler), sizeof(aes_encrypt_ctx));
	memcpy(context.BufferFor(clone->fDecryptScheduler),
		context.BufferFor(fDecryptScheduler), sizeof(aes_decrypt_ctx));
	clone->fMode = fMode;

	return clone;
}


void
AESAlgorithm::Decrypt(ThreadContext& context, uint8 *data, size_t length)
{
//dprintf("  aes-decrypt-pre:  %x (%d: %x)\n", *(int*)data, fDecryptScheduler, *(int*)context.BufferFor(fDecryptScheduler));
	aes_decrypt(data, data,
		(const aes_decrypt_ctx*)context.BufferFor(fDecryptScheduler));
//dprintf("  aes-decrypt-post: %x\n", *(int*)data);
}


void
AESAlgorithm::Encrypt(ThreadContext& context, uint8 *data, size_t length)
{
//dprintf("  aes-encrypt-pre:  %x\n", *(int*)data);
	aes_encrypt(data, data,
		(const aes_encrypt_ctx*)context.BufferFor(fEncryptScheduler));
//dprintf("  aes-encrypt-post: %x\n", *(int*)data);
}


void
AESAlgorithm::SetMode(EncryptionMode* mode)
{
	if (mode == NULL)
		fMode = MODE_XTS;
	else
		fMode = mode->Type();
}


//	#pragma mark - Encryption modes


XTSMode::XTSMode()
	:
	fAlgorithm(NULL),
	fSecondaryAlgorithm(NULL)
{
}


XTSMode::~XTSMode()
{
	delete fSecondaryAlgorithm;
}


status_t
XTSMode::Init(ThreadContext& context, EncryptionAlgorithm* algorithm)
{
	if (algorithm == NULL)
		return B_BAD_VALUE;

	fAlgorithm = algorithm;
	fAlgorithm->SetMode(this);

	fSecondaryAlgorithm = algorithm->Clone(context);
	if (fSecondaryAlgorithm == NULL)
		return B_NO_MEMORY;

	return B_OK;
}


status_t
XTSMode::SetKey(ThreadContext& context, const uint8* key, size_t keyLength)
{
//dprintf("xts key: %x\n", *(int*)key);
	return fSecondaryAlgorithm->SetKey(context, key, keyLength);
}


status_t
XTSMode::SetCompleteKey(ThreadContext& context, const uint8* key,
	size_t keyLength)
{
	return SetKey(context, key + KEY_SIZE, KEY_SIZE);
}


void
XTSMode::SetBlockOffset(off_t offset)
{
}


void
XTSMode::DecryptBlock(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 whiteningValue[BYTES_PER_XTS_BLOCK];
	uint8 byteBufUnitNo[BYTES_PER_XTS_BLOCK];
	uint64* bufPtr = (uint64*)data;
	uint32 startBlock = 0;
	uint32 endBlock, block;
	uint64 blockCount, dataUnitNo;
	uint8 finalCarry;

	// Convert the 64-bit data unit number into a little-endian 16-byte array.
	dataUnitNo = blockIndex;
	*((uint64*)byteBufUnitNo) = B_HOST_TO_LENDIAN_INT64(dataUnitNo);
	*((uint64*)byteBufUnitNo + 1) = 0;

	//ASSERT((length % BYTES_PER_XTS_BLOCK) == 0);

	blockCount = length / BYTES_PER_XTS_BLOCK;

	// Process all blocks in the buffer
	while (blockCount > 0) {
		if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
			endBlock = startBlock + (uint32)blockCount;
		else
			endBlock = BLOCKS_PER_XTS_DATA_UNIT;

		uint64* whiteningValuePtr64 = (uint64*)whiteningValue;

		// Encrypt the data unit number using the secondary key (in order to
		// generate the first whitening value for this data unit)
		*whiteningValuePtr64 = *((uint64*)byteBufUnitNo);
		*(whiteningValuePtr64 + 1) = 0;
		fSecondaryAlgorithm->Encrypt(context, (uint8*)whiteningValue,
			BYTES_PER_XTS_BLOCK);

		// Generate (and apply) subsequent whitening values for blocks in this
		// data unit and decrypt all relevant blocks in this data unit
		for (block = 0; block < endBlock; block++) {
			if (block >= startBlock) {
				// Post-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr-- ^= *whiteningValuePtr64--;

				// Actual decryption
				fAlgorithm->Decrypt(context, (uint8*)bufPtr,
					BYTES_PER_XTS_BLOCK);

				// Pre-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr++ ^= *whiteningValuePtr64;
			}
			else
				whiteningValuePtr64++;

			// Derive the next whitening value

#if BYTE_ORDER == LITTLE_ENDIAN
			// Little-endian platforms
			finalCarry = (*whiteningValuePtr64 & 0x8000000000000000ULL)
				? 135 : 0;

			*whiteningValuePtr64-- <<= 1;

			if (*whiteningValuePtr64 & 0x8000000000000000ULL)
				*(whiteningValuePtr64 + 1) |= 1;

			*whiteningValuePtr64 <<= 1;
#else
			// Big-endian platforms
			finalCarry = (*whiteningValuePtr64 & 0x80) ? 135 : 0;

			*whiteningValuePtr64 = B_HOST_TO_LENDIAN_INT64(
				B_HOST_TO_LENDIAN_INT64(*whiteningValuePtr64) << 1);

			whiteningValuePtr64--;

			if (*whiteningValuePtr64 & 0x80)
				*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;

			*whiteningValuePtr64 = B_HOST_TO_LENDIAN_INT64(
				B_HOST_TO_LENDIAN_INT64(*whiteningValuePtr64) << 1);
#endif

			whiteningValue[0] ^= finalCarry;
		}

		blockCount -= endBlock - startBlock;
		startBlock = 0;
		dataUnitNo++;
		*((uint64*)byteBufUnitNo) = B_HOST_TO_LENDIAN_INT64(dataUnitNo);
	}

	memset(whiteningValue, 0, sizeof(whiteningValue));
}


void
XTSMode::EncryptBlock(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 whiteningValue[BYTES_PER_XTS_BLOCK];
	uint8 byteBufUnitNo[BYTES_PER_XTS_BLOCK];
	uint64* bufPtr = (uint64*)data;
	uint32 startBlock = 0;
	uint32 endBlock, block;
	uint64 blockCount, dataUnitNo;
	uint8 finalCarry;

	// Convert the 64-bit data unit number into a little-endian 16-byte array.
	dataUnitNo = blockIndex;
	*((uint64*)byteBufUnitNo) = B_HOST_TO_LENDIAN_INT64(dataUnitNo);
	*((uint64*)byteBufUnitNo + 1) = 0;

	//ASSERT((length % BYTES_PER_XTS_BLOCK) == 0);

	blockCount = length / BYTES_PER_XTS_BLOCK;

	// Process all blocks in the buffer
	while (blockCount > 0) {
		if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
			endBlock = startBlock + (uint32)blockCount;
		else
			endBlock = BLOCKS_PER_XTS_DATA_UNIT;

		uint64* whiteningValuePtr64 = (uint64*)whiteningValue;

		// Encrypt the data unit number using the secondary key (in order to
		// generate the first whitening value for this data unit)
		*whiteningValuePtr64 = *((uint64*)byteBufUnitNo);
		*(whiteningValuePtr64 + 1) = 0;
		fSecondaryAlgorithm->Encrypt(context, (uint8*)whiteningValue,
			BYTES_PER_XTS_BLOCK);

		// Generate (and apply) subsequent whitening values for blocks in this
		// data unit and encrypt all relevant blocks in this data unit
		for (block = 0; block < endBlock; block++) {
			if (block >= startBlock) {
				// Pre-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr-- ^= *whiteningValuePtr64--;

				// Actual encryption
				fAlgorithm->Encrypt(context, (uint8*)bufPtr,
					BYTES_PER_XTS_BLOCK);

				// Post-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr++ ^= *whiteningValuePtr64;
			}
			else
				whiteningValuePtr64++;

			// Derive the next whitening value

#if BYTE_ORDER == LITTLE_ENDIAN
			// Little-endian platforms
			finalCarry = (*whiteningValuePtr64 & 0x8000000000000000ULL)
				? 135 : 0;

			*whiteningValuePtr64-- <<= 1;

			if (*whiteningValuePtr64 & 0x8000000000000000ULL)
				*(whiteningValuePtr64 + 1) |= 1;

			*whiteningValuePtr64 <<= 1;
#else
			// Big-endian platforms
			finalCarry = (*whiteningValuePtr64 & 0x80) ? 135 : 0;

			*whiteningValuePtr64 = B_HOST_TO_LENDIAN_INT64(
				B_HOST_TO_LENDIAN_INT64(*whiteningValuePtr64) << 1);

			whiteningValuePtr64--;

			if (*whiteningValuePtr64 & 0x80)
				*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;

			*whiteningValuePtr64 = B_HOST_TO_LENDIAN_INT64(
				B_HOST_TO_LENDIAN_INT64(*whiteningValuePtr64) << 1);
#endif

			whiteningValue[0] ^= finalCarry;
		}

		blockCount -= endBlock - startBlock;
		startBlock = 0;
		dataUnitNo++;
		*((uint64*)byteBufUnitNo) = B_HOST_TO_LENDIAN_INT64(dataUnitNo);
	}

	memset(whiteningValue, 0, sizeof(whiteningValue));
}


void
XTSMode::Decrypt(ThreadContext& context, uint8 *data, size_t length)
{
	DecryptBlock(context, data, length, 0);
}


void
XTSMode::Encrypt(ThreadContext& context, uint8 *data, size_t length)
{
	EncryptBlock(context, data, length, 0);
}


//	#pragma mark -


LRWMode::LRWMode()
	:
	fAlgorithm(NULL),
	fOffset(0)
{
}


LRWMode::~LRWMode()
{
}


status_t
LRWMode::Init(ThreadContext& context, EncryptionAlgorithm* algorithm)
{
	if (algorithm == NULL)
		return B_BAD_VALUE;

	fGaloisField = context.AddBuffer(sizeof(struct galois_field_context));
	if (fGaloisField < 0)
		return B_NO_MEMORY;

	fAlgorithm = algorithm;
	fAlgorithm->SetMode(this);
	return B_OK;
}


status_t
LRWMode::SetKey(ThreadContext& context, const uint8* key, size_t keyLength)
{
//dprintf("lrw key: %x\n", *(int*)key);
	gf128_tab64_init(key,
		(struct galois_field_context*)context.BufferFor(fGaloisField));

	return B_OK;
}


status_t
LRWMode::SetCompleteKey(ThreadContext& context, const uint8* key,
	size_t keyLength)
{
	return SetKey(context, key, keyLength);
}


void
LRWMode::SetBlockOffset(off_t offset)
{
	fOffset = offset;
}


void
LRWMode::DecryptBlock(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	int b;

	blockIndex = ((blockIndex - fOffset) << 5) + 1;
	*(uint64*)i = B_HOST_TO_BENDIAN_INT64(blockIndex);

	for (b = 0; b < length >> 4; b++) {
		gf128_mul_by_tab64(i, t,
			(galois_field_context*)context.BufferFor(fGaloisField));
//dprintf("  t: %x\n", *(int*)t);
		xor128((uint64*)data, (uint64 *)t);

		fAlgorithm->Decrypt(context, data, 16);

		xor128((uint64*)data, (uint64*)t);

		data += 16;

		if (i[7] != 0xff)
			i[7]++;
		else {
			*(uint64*)i = B_HOST_TO_BENDIAN_INT64(
				B_BENDIAN_TO_HOST_INT64(*(uint64*)i) + 1);
		}
	}

	memset(t, 0, sizeof (t));
}


void
LRWMode::EncryptBlock(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	uint32 b;

	blockIndex = ((blockIndex - fOffset) << 5) + 1;
	*(uint64*)i = B_HOST_TO_BENDIAN_INT64(blockIndex);

	for (b = 0; b < length >> 4; b++) {
		gf128_mul_by_tab64(i, t,
			(galois_field_context*)context.BufferFor(fGaloisField));
		xor128((uint64*)data, (uint64*)t);

		fAlgorithm->Encrypt(context, data, 16);

		xor128((uint64*)data, (uint64*)t);

		data += 16;

		if (i[7] != 0xff)
			i[7]++;
		else {
			*(uint64*)i = B_HOST_TO_BENDIAN_INT64(
				B_BENDIAN_TO_HOST_INT64(*(uint64*)i) + 1);
		}
	}

	memset(t, 0, sizeof (t));
}


void
LRWMode::Decrypt(ThreadContext& context, uint8 *data, size_t length)
{
	DecryptBlock(context, data, length, fOffset);
}


void
LRWMode::Encrypt(ThreadContext& context, uint8 *data, size_t length)
{
	EncryptBlock(context, data, length, fOffset);
}


//	#pragma mark - exported API


CryptContext::CryptContext()
	:
	fAlgorithm(NULL),
	fMode(NULL),
	fThreadContexts(NULL)
{
}


CryptContext::~CryptContext()
{
	if (fThreadContexts != NULL) {
		for (int32 i = 0; i < sThreadCount; i++) {
			delete fThreadContexts[i];
		}

		delete[] fThreadContexts;
	}
}


status_t
CryptContext::Init(encryption_algorithm algorithm, encryption_mode mode,
	const uint8* key, size_t keyLength)
{
	_Uninit();

	ThreadContext threadContext;

	fAlgorithm = create_algorithm(algorithm);
	if (fAlgorithm == NULL)
		return B_NO_MEMORY;

	status_t status = fAlgorithm->Init(threadContext);
	if (status != B_OK)
		return status;

	fMode = create_mode(mode);
	if (fMode == NULL)
		return B_NO_MEMORY;

	status = fMode->Init(threadContext, fAlgorithm);
	if (status != B_OK)
		return status;

	fThreadContexts = new(std::nothrow) ThreadContext*[sThreadCount];
	if (fThreadContexts == NULL)
		return B_NO_MEMORY;

	for (int32 i = 0; i < sThreadCount; i++) {
		fThreadContexts[i] = new ThreadContext(threadContext);
	}

	return SetKey(key, keyLength);
}


status_t
CryptContext::SetKey(const uint8* key, size_t keyLength)
{
	for (int32 i = 0; i < sThreadCount; i++) {
		status_t status = fAlgorithm->SetCompleteKey(*fThreadContexts[i], key,
			keyLength);
		if (status == B_OK)
			status = fMode->SetCompleteKey(*fThreadContexts[i], key, keyLength);

		if (status != B_OK)
			return status;
	}

	return B_OK;
}


void
CryptContext::DecryptBlock(uint8 *buffer, size_t length, uint64 blockIndex)
{
	fMode->DecryptBlock(*(fThreadContexts[0]), buffer, length, blockIndex);
}


void
CryptContext::EncryptBlock(uint8 *buffer, size_t length, uint64 blockIndex)
{
	fMode->EncryptBlock(*(fThreadContexts[0]), buffer, length, blockIndex);
}


void
CryptContext::Decrypt(uint8 *buffer, size_t length)
{
	fMode->Decrypt(*(fThreadContexts[0]), buffer, length);
}


void
CryptContext::Encrypt(uint8 *buffer, size_t length)
{
	fMode->Encrypt(*(fThreadContexts[0]), buffer, length);
}


void
CryptContext::_Uninit()
{
	delete fAlgorithm;
	delete fMode;
	delete fThreadContexts;

	fAlgorithm = NULL;
	fMode = NULL;
	fThreadContexts = NULL;
}


// #pragma mark -


VolumeCryptContext::VolumeCryptContext()
{
}


VolumeCryptContext::~VolumeCryptContext()
{
}


status_t
VolumeCryptContext::Detect(int fd, const uint8* key, uint32 keyLength)
{
	off_t headerOffset;
	uint8 buffer[BLOCK_SIZE];
	true_crypt_header header;
	return _Detect(fd, key, keyLength, headerOffset, buffer, header);
}


status_t
VolumeCryptContext::Setup(int fd, const uint8* key, uint32 keyLength,
	const uint8* random, uint32 randomLength)
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
VolumeCryptContext::SetPassword(int fd, const uint8* oldKey,
	uint32 oldKeyLength, const uint8* newKey, uint32 newKeyLength)
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

dprintf("HEADER OFFSET: %Ld\n", headerOffset);
dprintf("NEW KEY: %s\n", newKey);
	return _WriteHeader(fd, newKey, newKeyLength, headerOffset, buffer);
}


status_t
VolumeCryptContext::_Detect(int fd, const uint8* key, uint32 keyLength,
	off_t& offset, uint8* buffer, true_crypt_header& header)
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
VolumeCryptContext::_Detect(int fd, off_t offset, off_t size, const uint8* key,
	uint32 keyLength, uint8* buffer, true_crypt_header& header)
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

	status_t status = Init(ALGORITHM_AES, MODE_XTS, diskKey, DISK_KEY_SIZE);
	if (status != B_OK)
		return status;

	memcpy(&header, encryptedHeader, sizeof(true_crypt_header));

	Decrypt((uint8*)&header, sizeof(true_crypt_header));

	if (!valid_true_crypt_header(header)) {
		dump_true_crypt_header(header);

		// Try with legacy encryption mode LRW instead
		status = Init(ALGORITHM_AES, MODE_LRW, diskKey, DISK_KEY_SIZE);
		if (status != B_OK)
			return status;

		memcpy(&header, encryptedHeader, sizeof(true_crypt_header));

		Decrypt((uint8*)&header, sizeof(true_crypt_header));

		if (!valid_true_crypt_header(header)) {
			dump_true_crypt_header(header);
			return B_PERMISSION_DENIED;
		}
	}

	if (header.RequiredProgramVersion() >= 0x700) {
		// TODO: test if the block size is really not 512 bytes
		dprintf("header version not yet supported!\n");
		return B_NOT_SUPPORTED;
	}

	// then init context with the keys from the unencrypted header

	SetKey(header.disk_key, sizeof(header.disk_key));

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

	fMode->SetBlockOffset(fOffset / BLOCK_SIZE);
	return B_OK;
}


//! Use key + salt to encrypt the header, and write it to disk.
status_t
VolumeCryptContext::_WriteHeader(int fd, const uint8* key, uint32 keyLength,
	off_t headerOffset, uint8* buffer)
{
	uint8 diskKey[DISK_KEY_SIZE];
	derive_key(key, keyLength, buffer, PKCS5_SALT_SIZE, diskKey, DISK_KEY_SIZE);

	status_t status = Init(ALGORITHM_AES, MODE_XTS, diskKey, DISK_KEY_SIZE);
	if (status != B_OK)
		return status;

	true_crypt_header& header = *(true_crypt_header*)&buffer[PKCS5_SALT_SIZE];
	Encrypt((uint8*)&header, BLOCK_SIZE - PKCS5_SALT_SIZE);

	ssize_t bytesWritten = write_pos(fd, headerOffset, buffer, BLOCK_SIZE);
	if (bytesWritten < 0)
		return errno;

	// use the decrypted header to init the volume encryption

	Decrypt((uint8*)&header, BLOCK_SIZE - PKCS5_SALT_SIZE);
	SetKey(header.disk_key, sizeof(header.disk_key));

	return B_OK;
}


//	#pragma mark - CryptTask


CryptTask::CryptTask(CryptContext& context, uint8* data, size_t length,
	uint64 blockIndex)
	:
	fContext(context),
	fData(data),
	fLength(length),
	fBlockIndex(blockIndex),
	fUsedThreadContexts(0)
{
	fJobBlocks = ((fLength / BLOCK_SIZE) + sThreadCount - 1) / sThreadCount;
	if (fJobBlocks < 1)
		fJobBlocks = 1;
}


Job*
CryptTask::CreateNextJob()
{
	if (IsDone())
		return NULL;

	CryptJob* job = CreateJob();
	_PrepareJob(job);
	return job;
}


void
CryptTask::Put(ThreadContext* threadContext)
{
	for (int32 i = 0; i < sThreadCount; i++) {
		if (fContext.fThreadContexts[i] == threadContext) {
			atomic_and(&fUsedThreadContexts, ~(1L << i));
			break;
		}
	}
}


void
CryptTask::_PrepareJob(CryptJob* job)
{
	size_t bytes = min_c(fJobBlocks * BLOCK_SIZE, fLength);
	job->SetTo(this, _Get(), fData, bytes, fBlockIndex);
	fData += bytes;
	fLength -= bytes;
	fBlockIndex += fJobBlocks;
}


ThreadContext*
CryptTask::_Get()
{
	for (int32 i = 0; i < sThreadCount; i++) {
		int32 bit = 1L << i;
		if ((fUsedThreadContexts & bit) == 0) {
			fUsedThreadContexts |= bit;
			return fContext.fThreadContexts[i];
		}
	}

	return NULL;
}


//	#pragma mark - DecryptTask


CryptJob*
DecryptTask::CreateJob()
{
	return new DecryptJob();
}


//	#pragma mark - EncryptTask


CryptJob*
EncryptTask::CreateJob()
{
	return new EncryptJob();
}


//	#pragma mark -


void
init_crypt()
{
	system_info info;
	if (get_system_info(&info) == B_OK)
		sThreadCount = info.cpu_count;
	if (sThreadCount == 0)
		sThreadCount = 1;
}


void
uninit_crypt()
{
}


void
derive_key(const uint8 *key, size_t keyLength, const uint8 *salt,
	size_t saltLength, uint8 *derivedKey, size_t derivedKeyLength)
{
	derive_key_ripemd160(key, keyLength, salt, saltLength, RIPEMD160_ITERATIONS,
		derivedKey, derivedKeyLength);
}

