/*
 * Copyright 2008-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 *
 * The XTS/LRW modes and the RIPE160 code is distributed under the
 * Truecrypt License.
 */


#include "crypt.h"

#include <ByteOrder.h>
#include <Drivers.h>
#include <KernelExport.h>

#include <errno.h>
#include <new>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "aes.h"
#include "crc32.h"
#include "gf_mul.h"
#include "ripemd160.h"


const uint32 kTrueCryptMagic = 'TRUE';

#define BLOCK_SIZE					512
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
	uint64	volume_creation_time;
	uint64	header_creation_time;
	uint64	hidden_size;
	uint8	_reserved[156];
	uint8	secondary_key[32];
	uint8	master_key[224];
} _PACKED;


class ThreadContext {
public:
	ThreadContext();
	ThreadContext(const ThreadContext& context);
	~ThreadContext();

	int32 AddBuffer(size_t size);
	void* BufferFor(int32 index);
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

	virtual void Decrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0) = 0;
	virtual void Encrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0) = 0;
	
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
 
	virtual void Decrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0);
	virtual void Encrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0);

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
 
	virtual void Decrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0);
	virtual void Encrypt(ThreadContext& context, uint8 *data, size_t length,
		uint64 blockIndex = 0);

	virtual encryption_mode Type() { return MODE_LRW; }

protected:
	EncryptionAlgorithm*	fAlgorithm;
	int32					fGaloisField;
};


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
	dprintf("version: %x\n", B_BENDIAN_TO_HOST_INT16(header.version));
	dprintf("required program version: %x\n", header.required_program_version);
	dprintf("crc checksum: %lu (%lu)\n",
		B_BENDIAN_TO_HOST_INT32(header.crc_checksum),
		crc32(header.secondary_key, 256));
	dprintf("volume creation time: %Ld\n", header.volume_creation_time);
	dprintf("header creation time: %Ld\n", header.header_creation_time);
	dprintf("hidden size: %Ld\n", B_BENDIAN_TO_HOST_INT64(header.hidden_size));
}


static bool
valid_true_crypt_header(true_crypt_header& header)
{
	return header.magic == B_HOST_TO_BENDIAN_INT32(kTrueCryptMagic)
		&& B_BENDIAN_TO_HOST_INT32(header.crc_checksum)
				== crc32(header.secondary_key, 256);
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


int32
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
ThreadContext::BufferFor(int32 index)
{
	return (void*)((uint8*)fBuffer + index);
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
//printf("%s-aes key: %x\n", fMode == MODE_LRW ? "lrw" : "xts", *(int*)key);
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
//printf("  aes-decrypt-pre:  %x (%d: %x)\n", *(int*)data, fDecryptScheduler, *(int*)context.BufferFor(fDecryptScheduler));
	aes_decrypt(data, data,
		(const aes_decrypt_ctx*)context.BufferFor(fDecryptScheduler));
//printf("  aes-decrypt-post: %x\n", *(int*)data);
}


void
AESAlgorithm::Encrypt(ThreadContext& context, uint8 *data, size_t length)
{
//printf("  aes-encrypt-pre:  %x\n", *(int*)data);
	aes_encrypt(data, data,
		(const aes_encrypt_ctx*)context.BufferFor(fEncryptScheduler));
//printf("  aes-encrypt-post: %x\n", *(int*)data);
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
printf("xts key: %x\n", *(int*)key);
	return fSecondaryAlgorithm->SetKey(context, key, keyLength);
}


status_t
XTSMode::SetCompleteKey(ThreadContext& context, const uint8* key,
	size_t keyLength)
{
	return fSecondaryAlgorithm->SetKey(context, key + KEY_SIZE, KEY_SIZE);
}


void
XTSMode::Decrypt(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 finalCarry;
	uint8 whiteningValue[BYTES_PER_XTS_BLOCK];
	uint8 byteBufUnitNo[BYTES_PER_XTS_BLOCK];
	uint64* bufPtr = (uint64*)data;
	uint32 startBlock = 0;//blockIndex;
	uint32 endBlock, block;
	uint64 blockCount, dataUnitNo;

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
			finalCarry = (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;

			*whiteningValuePtr64-- <<= 1;

			if (*whiteningValuePtr64 & 0x8000000000000000ULL)
				*(whiteningValuePtr64 + 1) |= 1;	

			*whiteningValuePtr64 <<= 1;
#else
			// Big-endian platforms
			finalCarry = (*whiteningValuePtr64 & 0x80) ? 135 : 0;

			*whiteningValuePtr64 = LE64(LE64(*whiteningValuePtr64) << 1);

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
XTSMode::Encrypt(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
}


//	#pragma mark -


LRWMode::LRWMode()
	:
	fAlgorithm(NULL)
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
printf("lrw key: %x\n", *(int*)key);
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
LRWMode::Decrypt(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	int b;

	blockIndex = (blockIndex << 5) + 1;
	*(uint64*)i = B_HOST_TO_BENDIAN_INT64(blockIndex);

	for (b = 0; b < length >> 4; b++) {
		gf128_mul_by_tab64(i, t,
			(galois_field_context*)context.BufferFor(fGaloisField));
//printf("  t: %x\n", *(int*)t);
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
LRWMode::Encrypt(ThreadContext& context, uint8 *data, size_t length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	uint32 b;

	blockIndex = (blockIndex << 5) + 1;
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

	SetKey(key, keyLength);

	fThreadContexts = new(std::nothrow) ThreadContext(threadContext);
	if (fThreadContexts == NULL)
		return B_NO_MEMORY;

	return B_OK;
}


status_t
CryptContext::SetKey(const uint8* key, size_t keyLength)
{
	fAlgorithm->SetCompleteKey(*fThreadContexts, key, keyLength);
	fMode->SetCompleteKey(*fThreadContexts, key, keyLength);
}


void
CryptContext::Decrypt(uint8 *buffer, size_t length, uint64 blockIndex)
{
	fMode->Decrypt(*fThreadContexts, buffer, length, blockIndex);
}


void
CryptContext::Encrypt(uint8 *buffer, size_t length, uint64 blockIndex)
{
	fMode->Encrypt(*fThreadContexts, buffer, length, blockIndex);
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


#if 0
void
encrypt_block_xts(crypt_context& context, uint8 *data, uint32 length,
	uint64 blockIndex)
{
	// TODO: implement!
#if 0
	uint8 finalCarry;
	uint8 whiteningValue [BYTES_PER_XTS_BLOCK];
	uint8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
	uint64 *whiteningValuePtr64 = (uint64 *) whiteningValue;
	uint64 *bufPtr = (uint64*)data;
	unsigned int startBlock = startCipherBlockNo, endBlock, block;
	uint64 blockCount, dataUnitNo;

	/* The encrypted data unit number (i.e. the resultant ciphertext block) is to be multiplied in the
	finite field GF(2^128) by j-th power of n, where j is the sequential plaintext/ciphertext block
	number and n is 2, a primitive element of GF(2^128). This can be (and is) simplified and implemented
	as a left shift of the preceding whitening value by one bit (with carry propagating). In addition, if
	the shift of the highest byte results in a carry, 135 is XORed into the lowest byte. The value 135 is
	derived from the modulus of the Galois Field (x^128+x^7+x^2+x+1). */

	// Convert the 64-bit data unit number into a little-endian 16-byte array. 
	// Note that as we are converting a 64-bit number into a 16-byte array we can always zero the last 8 bytes.
	dataUnitNo = startDataUnitNo;
	*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
	*((uint64 *) byteBufUnitNo + 1) = 0;

	if (length % BYTES_PER_XTS_BLOCK)
		TC_THROW_FATAL_EXCEPTION;

	blockCount = length / BYTES_PER_XTS_BLOCK;

	// Process all blocks in the buffer
	while (blockCount > 0)
	{
		if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
			endBlock = startBlock + (unsigned int) blockCount;
		else
			endBlock = BLOCKS_PER_XTS_DATA_UNIT;

		whiteningValuePtr64 = (uint64 *) whiteningValue;

		// Encrypt the data unit number using the secondary key (in order to generate the first 
		// whitening value for this data unit)
		*whiteningValuePtr64 = *((uint64 *) byteBufUnitNo);
		*(whiteningValuePtr64 + 1) = 0;
		secondaryCipher.EncryptBlock (whiteningValue);

		// Generate (and apply) subsequent whitening values for blocks in this data unit and
		// encrypt all relevant blocks in this data unit
		for (block = 0; block < endBlock; block++)
		{
			if (block >= startBlock)
			{
				// Pre-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr-- ^= *whiteningValuePtr64--;

				// Actual encryption
				cipher.EncryptBlock (reinterpret_cast <uint8 *> (bufPtr));

				// Post-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr++ ^= *whiteningValuePtr64;
			}
			else
				whiteningValuePtr64++;

			// Derive the next whitening value

#if BYTE_ORDER == LITTLE_ENDIAN

			// Little-endian platforms

			finalCarry = 
				(*whiteningValuePtr64 & 0x8000000000000000ULL) ?
				135 : 0;

			*whiteningValuePtr64-- <<= 1;

			if (*whiteningValuePtr64 & 0x8000000000000000ULL)
				*(whiteningValuePtr64 + 1) |= 1;	

			*whiteningValuePtr64 <<= 1;
#else

			// Big-endian platforms

			finalCarry = 
				(*whiteningValuePtr64 & 0x80) ?
				135 : 0;

			*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);

			whiteningValuePtr64--;

			if (*whiteningValuePtr64 & 0x80)
				*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;	

			*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
#endif

			whiteningValue[0] ^= finalCarry;
		}

		blockCount -= endBlock - startBlock;
		startBlock = 0;
		dataUnitNo++;
		*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
	}

	FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
#endif
}
#endif


VolumeCryptContext::VolumeCryptContext()
{
}


VolumeCryptContext::~VolumeCryptContext()
{
}


status_t
VolumeCryptContext::Detect(int fd, const uint8* key, uint32 keyLength)
{
	off_t size;
	status_t status = get_size(fd, size);
	if (status < B_OK)
		return status;

	fOffset = BLOCK_SIZE;
	fSize = size - BLOCK_SIZE;
	fHidden = false;

	if (_Detect(fd, 0, key, keyLength) == B_OK)
		return B_OK;

	return _Detect(fd, size - HIDDEN_HEADER_OFFSET, key, keyLength);
}


status_t
VolumeCryptContext::Setup(int fd, const uint8* key, uint32 keyLength,
	const uint8* random, uint32 randomLength)
{
	return B_ERROR;
#if 0
	off_t size;
	status_t status = get_size(fd, size);
	if (status < B_OK)
		return status;

	context.offset = BLOCK_SIZE;
	context.size = size - BLOCK_SIZE;
	context.hidden = false;

	memcpy(context.key_salt, random, PKCS5_SALT_SIZE);
	random += PKCS5_SALT_SIZE;

	true_crypt_header header;
	memcpy(header.salt, context.key_salt, PKCS5_SALT_SIZE);
	header.magic = B_HOST_TO_BENDIAN_INT32(kTrueCryptMagic);
	header.version = B_HOST_TO_BENDIAN_INT16(0x1000);
	header.required_program_version = B_HOST_TO_BENDIAN_INT16(0x1000);
	header.volume_creation_time
		= B_HOST_TO_BENDIAN_INT64(real_time_clock_usecs());
	header.header_creation_time
		= B_HOST_TO_BENDIAN_INT64(real_time_clock_usecs());
	header.hidden_size = 0;
	memset(header._reserved, 0, sizeof(header._reserved));
	memcpy(header.secondary_key, random, SECONDARY_KEY_SIZE);
	random += SECONDARY_KEY_SIZE;
	memcpy(header.master_key, random, sizeof(header.master_key));
	random += sizeof(header.master_key);
	header.crc_checksum = crc32(header.secondary_key, 256);

	// use key + salt to encrypt the header, and write it to disk

	uint8 diskKey[256];
	derive_key_ripemd160(key, keyLength, context.key_salt, PKCS5_SALT_SIZE,
		RIPEMD160_ITERATIONS, diskKey, SECONDARY_KEY_SIZE + 32);
	memcpy(context.secondary_key, diskKey, SECONDARY_KEY_SIZE);
	gf128_tab64_init(context.secondary_key, &context.gf_context);
	init_key(context, diskKey + SECONDARY_KEY_SIZE);

	encrypt_buffer(context, (uint8*)&header.magic,
		BLOCK_SIZE - PKCS5_SALT_SIZE);

	ssize_t bytesWritten = write_pos(fd, 0, &header, BLOCK_SIZE);
	if (bytesWritten < 0)
		return errno;

	// use the decrypted header to init the volume encryption

	decrypt_buffer(context, (uint8*)&header.magic,
		BLOCK_SIZE - PKCS5_SALT_SIZE);

	init_key(context, header.master_key);
	memcpy(context.secondary_key, header.secondary_key, SECONDARY_KEY_SIZE);
	gf128_tab64_init(context.secondary_key, &context.gf_context);

	return B_OK;
#endif
}


status_t
VolumeCryptContext::_Detect(int fd, off_t offset, const uint8* key,
	uint32 keyLength)
{
	uint8 buffer[BLOCK_SIZE];
	if (read_pos(fd, offset, buffer, BLOCK_SIZE) != BLOCK_SIZE)
		return B_ERROR;

	// decrypt header first

	uint8* encryptedHeader = buffer + PKCS5_SALT_SIZE;
	uint8* salt = buffer;
	uint8 diskKey[256];

	derive_key(key, keyLength, salt, PKCS5_SALT_SIZE, diskKey, DISK_KEY_SIZE);
printf("salt %x, key %x\n", *(int*)salt, *(int*)diskKey);

	status_t status = Init(ALGORITHM_AES, MODE_XTS, diskKey, DISK_KEY_SIZE);
	if (status != B_OK)
		return status;

	true_crypt_header header;
	memcpy(&header, encryptedHeader, sizeof(true_crypt_header));

	Decrypt((uint8*)&header, sizeof(true_crypt_header));

	if (!valid_true_crypt_header(header)) {
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

	dump_true_crypt_header(header);

	// then init context with the keys from the unencrypted header

	SetKey(header.master_key, sizeof(header.master_key));

#if 0
	if (offset != 0) {
		// this is a hidden drive, take over the size from the header
		context.size = B_BENDIAN_TO_HOST_INT64(header.hidden_size);
		context.offset = offset - context.size;
		context.hidden = true;
	}
#endif

	return B_OK;
}


//	#pragma mark -


void
derive_key(const uint8 *key, size_t keyLength, const uint8 *salt,
	size_t saltLength, uint8 *derivedKey, size_t derivedKeyLength)
{
	derive_key_ripemd160(key, keyLength, salt, saltLength, RIPEMD160_ITERATIONS,
		derivedKey, derivedKeyLength);
}

