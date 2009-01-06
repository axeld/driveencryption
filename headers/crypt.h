/*
 * Copyright 2008-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef CRYPT_H
#define CRYPT_H


#include <SupportDefs.h>


#define PKCS5_SALT_SIZE		64
#define KEY_SIZE			32

class EncryptionAlgorithm;
class EncryptionMode;
class ThreadContext;

enum encryption_algorithm {
	ALGORITHM_AES
};

enum encryption_mode {
	MODE_LRW,
	MODE_XTS
};

class CryptContext {
public:
	CryptContext();
	virtual ~CryptContext();

	status_t Init(encryption_algorithm algorithmType,
		encryption_mode modeType, const uint8* key, size_t keyLength);
	status_t SetKey(const uint8* key, size_t keyLength);

	void DecryptBlock(uint8 *buffer, size_t length, uint64 blockIndex);
	void EncryptBlock(uint8 *buffer, size_t length, uint64 blockIndex);

	void Decrypt(uint8 *buffer, size_t length);
	void Encrypt(uint8 *buffer, size_t length);

protected:
	void _Uninit();

	EncryptionAlgorithm*	fAlgorithm;
	EncryptionMode*			fMode;
	ThreadContext*			fThreadContexts;
};

class VolumeCryptContext : public CryptContext {
public:
	VolumeCryptContext();
	~VolumeCryptContext();

	status_t Detect(int fd, const uint8* key, uint32 keyLength);
	status_t Setup(int fd, const uint8* key, uint32 keyLength,
		const uint8* random, uint32 randomLength);

	off_t Offset() const { return fOffset; }
	off_t Size() const { return fSize; }
	bool IsHidden() const { return fHidden; }

protected:
	status_t _Detect(int fd, off_t offset, off_t size, const uint8* key,
		uint32 keyLength);

	off_t					fOffset;
	off_t					fSize;
	bool					fHidden;
};

void derive_key(const uint8 *key, size_t keyLength, const uint8 *salt,
	size_t saltLength, uint8 *derivedKey, size_t derivedKeyLength);

#endif	// CRYPT_H
