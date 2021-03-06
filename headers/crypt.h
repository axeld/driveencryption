/*
 * Copyright 2008-2020, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef CRYPT_H
#define CRYPT_H


#include <SupportDefs.h>

#include "Worker.h"


#define PKCS5_SALT_SIZE		64
#define KEY_SIZE			32
#define BLOCK_SIZE			512

class CryptJob;
class DecryptJob;
class EncryptJob;
class EncryptionAlgorithm;
class EncryptionMode;
class ThreadContext;
struct true_crypt_header;

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

protected:
	friend class CryptTask;

	EncryptionAlgorithm*	fAlgorithm;
	EncryptionMode*			fMode;
	ThreadContext**			fThreadContexts;
	EncryptJob*				fEncryptJobs;
	DecryptJob*				fDecryptJobs;
};

class VolumeCryptContext : public CryptContext {
public:
	VolumeCryptContext();
	~VolumeCryptContext();

	status_t Detect(int fd, const uint8* key, uint32 keyLength);
	status_t Setup(int fd, const uint8* key, uint32 keyLength,
		const uint8* random, uint32 randomLength);
	status_t SetPassword(int fd, const uint8* oldKey, uint32 oldKeyLength,
		const uint8* newKey, uint32 newKeyLength);

	off_t Offset() const { return fOffset; }
	off_t Size() const { return fSize; }
	bool IsHidden() const { return fHidden; }

protected:
	status_t _Detect(int fd, const uint8* key, uint32 keyLength, off_t& offset,
		uint8* buffer, true_crypt_header& header);
	status_t _Detect(int fd, off_t offset, off_t size, const uint8* key,
		uint32 keyLength, uint8* buffer, true_crypt_header& header);
	status_t _WriteHeader(int fd, const uint8* key, uint32 keyLength,
		off_t headerOffset, uint8* buffer);

	off_t					fOffset;
	off_t					fSize;
	bool					fHidden;
};

class CryptTask : public Task {
public:
	CryptTask(CryptContext& context, uint8* data, size_t length,
		uint64 blockIndex);
	virtual ~CryptTask() {}

protected:
	EncryptionMode* Mode() { return fContext.fMode; }
	bool IsDone() const { return fLength == 0; }
	EncryptJob* EncryptJobs(int32 id);
	DecryptJob* DecryptJobs(int32 id);

	virtual Job* CreateNextJob(int32 id);
	virtual CryptJob* CreateJob(int32 id) = 0;

private:
	bool _PrepareJob(CryptJob* job, int32 id);
	ThreadContext* _Get();

protected:
	CryptContext&	fContext;
	uint8*			fData;
	size_t			fLength;
	uint64			fBlockIndex;
	size_t			fJobBlocks;
};

class DecryptTask : public CryptTask {
public:
	DecryptTask(CryptContext& context, uint8* data, size_t length,
		uint64 blockIndex)
		:
		CryptTask(context, data, length, blockIndex)
	{
	}

protected:
	virtual CryptJob* CreateJob(int32 id);
};

class EncryptTask : public CryptTask {
public:
	EncryptTask(CryptContext& context, uint8* data, size_t length,
		uint64 blockIndex)
		:
		CryptTask(context, data, length, blockIndex)
	{
	}

protected:
	virtual CryptJob* CreateJob(int32 id);
};


void init_crypt();
void uninit_crypt();

void derive_key(const uint8 *key, size_t keyLength, const uint8 *salt,
	size_t saltLength, uint8 *derivedKey, size_t derivedKeyLength);

#endif	// CRYPT_H
