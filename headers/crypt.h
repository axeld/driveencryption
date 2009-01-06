/*
 * Copyright 2008-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef CRYPT_H
#define CRYPT_H


#include <SupportDefs.h>


#define PKCS5_SALT_SIZE		64
#define SECONDARY_KEY_SIZE	32

class EncryptionAlgorithm;
class EncryptionMode;

struct crypt_context {
	uint8					key_salt[PKCS5_SALT_SIZE];
	uint8					secondary_key[SECONDARY_KEY_SIZE];
	off_t					offset;
	off_t					size;
	bool					hidden;
	EncryptionAlgorithm*	algorithm;
	EncryptionMode*			mode;
};


void derive_key_ripemd160(const uint8 *key, int keyLength, const uint8 *salt,
	int saltLength, int iterations, uint8 *diskKey, int diskKeyLength);

void encrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length);
void decrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length);

status_t detect_drive(crypt_context& context, int fd, const uint8* key,
	uint32 keyLength);
status_t setup_drive(crypt_context& context, int fd, const uint8* key,
	uint32 keyLength, const uint8* random, uint32 randomLength);
void init_context(crypt_context& context);

#endif	// CRYPT_H
