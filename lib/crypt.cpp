#include "crypt.h"

#include <ByteOrder.h>
#include <Drivers.h>
#include <KernelExport.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ripemd160.h"
#include "aes.h"
#include "crc32.h"


const uint32 kTrueCryptMagic = 'TRUE';

#define BLOCK_SIZE					512
#define HIDDEN_HEADER_OFFSET		1536
#define RIPEMD160_ITERATIONS		2000
#define BYTES_PER_XTS_BLOCK			16
#define BLOCKS_PER_XTS_DATA_UNIT	(BLOCK_SIZE / BYTES_PER_XTS_BLOCK)


struct true_crypt_header {
	uint8	salt[PKCS5_SALT_SIZE];
	uint32	magic;
	uint16	version;
	uint16	required_program_version;
	uint32	crc_checksum;
	uint64	volume_creation_time;
	uint64	header_creation_time;
	uint64	hidden_size;
	uint8	_reserved[156];
	uint8	secondary_key[SECONDARY_KEY_SIZE];
	uint8	master_key[224];
} _PACKED;


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
	//dprintf("magic: %.4s\n", header.magic);
	dprintf("version: %x\n", header.version);
	dprintf("required program version: %x\n", header.required_program_version);
	dprintf("crc checksum: %ld\n", header.crc_checksum);
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


static status_t
detect(crypt_context& context, int fd, off_t offset, const uint8* key,
	uint32 keyLength)
{
	uint8 buffer[BLOCK_SIZE];
	if (read_pos(fd, offset, buffer, BLOCK_SIZE) != BLOCK_SIZE)
		return B_ERROR;

	// decrypt header first

	true_crypt_header& header = *(true_crypt_header*)buffer;
	uint8 diskKey[256];
	memcpy(context.key_salt, header.salt, PKCS5_SALT_SIZE);

	derive_key_ripemd160(key, keyLength, context.key_salt, PKCS5_SALT_SIZE,
		RIPEMD160_ITERATIONS, diskKey, SECONDARY_KEY_SIZE + 32);
	memcpy(context.secondary_key, diskKey, SECONDARY_KEY_SIZE);
	gf128_tab64_init(context.secondary_key, &context.gf_context);
	init_key(context, diskKey + SECONDARY_KEY_SIZE);

	decrypt_buffer(context, buffer + PKCS5_SALT_SIZE,
		BLOCK_SIZE - PKCS5_SALT_SIZE);
	if (!valid_true_crypt_header(header)) {
		// Try with legacy encryption mode LRW instead
		context.decrypt_block = decrypt_block_lrw;
		context.encrypt_block = encrypt_block_lrw;

		decrypt_buffer(context, buffer + PKCS5_SALT_SIZE,
			BLOCK_SIZE - PKCS5_SALT_SIZE);
		if (!valid_true_crypt_header(header)) {
	dump_true_crypt_header(header);
			return B_PERMISSION_DENIED;
		}
	}

	dump_true_crypt_header(header);

	// then init context with the keys from the unencrypted header

	init_key(context, header.master_key);
	memcpy(context.secondary_key, header.secondary_key, SECONDARY_KEY_SIZE);
	gf128_tab64_init(context.secondary_key, &context.gf_context);

	if (offset != 0) {
		// this is a hidden drive, take over the size from the header
		context.size = B_BENDIAN_TO_HOST_INT64(header.hidden_size);
		context.offset = offset - context.size;
		context.hidden = true;
	}

	return B_OK;
}


//	#pragma mark - exported API


status_t
init_key(crypt_context& context, uint8* diskKey)
{
	if (aes_encrypt_key(diskKey, 32, (aes_encrypt_ctx *)context.key_schedule)
			!= EXIT_SUCCESS)
		return B_ERROR;

	if (aes_decrypt_key(diskKey, 32, (aes_decrypt_ctx *)(context.key_schedule
			+ sizeof(aes_encrypt_ctx))) != EXIT_SUCCESS)
		return B_ERROR;

	return B_OK;
}


void
encrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length)
{
	context.encrypt_block(context, (uint8 *)buffer, length, 0);
}


void
decrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length)
{
	context.decrypt_block(context, (uint8 *)buffer, length, 0);
}


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


void
decrypt_block_xts(crypt_context& context, uint8 *data, uint32 length,
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
		//EncipherBlock (cipher, whiteningValue, ks2);
		aes_encrypt(whiteningValue, whiteningValue,
			(const aes_encrypt_ctx*)context.key_schedule);

		// Generate (and apply) subsequent whitening values for blocks in this
		// data unit and decrypt all relevant blocks in this data unit
		for (block = 0; block < endBlock; block++) {
			if (block >= startBlock) {
				// Post-whitening
				*bufPtr++ ^= *whiteningValuePtr64++;
				*bufPtr-- ^= *whiteningValuePtr64--;

				// Actual decryption
				//DecipherBlock (cipher, bufPtr, ks);
				aes_decrypt(whiteningValue, whiteningValue,
					(const aes_decrypt_ctx*)((char*)context.key_schedule
						+ sizeof(aes_encrypt_ctx)));

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
encrypt_block_lrw(crypt_context& context, uint8* data, uint32 length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	uint32 b;

	blockIndex = (blockIndex << 5) + 1;
	*(uint64*)i = B_HOST_TO_BENDIAN_INT64(blockIndex);

	for (b = 0; b < length >> 4; b++) {
		gf128_mul_by_tab64(i, t, &context.gf_context);
		xor128((uint64*)data, (uint64*)t);

		aes_encrypt(data, data, (const aes_encrypt_ctx*)context.key_schedule);

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
decrypt_block_lrw(crypt_context& context, uint8* data, uint32 length,
	uint64 blockIndex)
{
	uint8 i[8];
	uint8 t[16];
	int b;

	blockIndex = (blockIndex << 5) + 1;
	*(uint64*)i = B_HOST_TO_BENDIAN_INT64(blockIndex);

	for (b = 0; b < length >> 4; b++) {
		gf128_mul_by_tab64(i, t, &context.gf_context);
		xor128((uint64*)data, (uint64 *)t);

		aes_decrypt(data, data, (const aes_decrypt_ctx*)
			((char*)context.key_schedule + sizeof(aes_encrypt_ctx)));

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


status_t
detect_drive(crypt_context& context, int fd, const uint8* key, uint32 keyLength)
{
	off_t size;
	status_t status = get_size(fd, size);
	if (status < B_OK)
		return status;

	context.offset = BLOCK_SIZE;
	context.size = size - BLOCK_SIZE;
	context.hidden = false;

	if (detect(context, fd, 0, key, keyLength) == B_OK)
		return B_OK;

	return detect(context, fd, size - HIDDEN_HEADER_OFFSET, key,
		keyLength);
}


status_t
setup_drive(crypt_context& context, int fd, const uint8* key, uint32 keyLength,
	const uint8* random, uint32 randomLength)
{
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
}


void
init_context(crypt_context& context)
{
	memset(&context, 0, sizeof(crypt_context));
	context.decrypt_block = decrypt_block_xts;
	context.encrypt_block = encrypt_block_xts;
}

