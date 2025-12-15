/*
 * Copyright 2008-2025, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef CRYPT_H
#define CRYPT_H


#include <SupportDefs.h>


#define PKCS5_SALT_SIZE		64
#define KEY_SIZE			32
#define BLOCK_SIZE			512

class EncryptionAlgorithm;
class ThreadContext;


enum encryption_algorithm {
	ALGORITHM_AES
};

enum encryption_mode {
	MODE_LRW,
	MODE_XTS
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


class CryptContext {
public:
	CryptContext();
	virtual ~CryptContext();

	status_t Init(encryption_algorithm algorithmType,
		encryption_mode modeType, const uint8* key, size_t keyLength);
	status_t SetKey(const uint8* key, size_t keyLength);
	void SetBlockOffset(off_t offset);

	void DecryptBlock(uint8 *buffer, size_t length, uint64 blockIndex);
	void EncryptBlock(uint8 *buffer, size_t length, uint64 blockIndex);

	void Decrypt(uint8 *buffer, size_t length);
	void Encrypt(uint8 *buffer, size_t length);

protected:
	virtual status_t _InitThreadContext(ThreadContext& threadContext);
	void _InitThreadContexts(int32 count);
	void _Uninit();

protected:
	friend class CryptTask;

	EncryptionAlgorithm*	fAlgorithm;
	EncryptionMode*			fMode;
	ThreadContext**			fThreadContexts;
	uint32					fThreadCount;
};


void derive_key(const uint8 *key, size_t keyLength, const uint8 *salt,
	size_t saltLength, uint8 *derivedKey, size_t derivedKeyLength);


#endif	// CRYPT_H
