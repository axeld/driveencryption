/*
 * Copyright 2008-2025, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef TASKS_H
#define TASKS_H


#include "crypt.h"
#include "Worker.h"


class CryptJob;
class DecryptJob;
class EncryptJob;


class TaskCryptContext : public CryptContext {
public:
	TaskCryptContext();
	virtual ~TaskCryptContext();

protected:
	virtual status_t _InitThreadContext(ThreadContext& threadContext);

protected:
	friend class CryptTask;

	EncryptJob*				fEncryptJobs;
	DecryptJob*				fDecryptJobs;
};


class CryptTask : public Task {
public:
	CryptTask(TaskCryptContext& context, uint8* data, size_t length,
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
	TaskCryptContext&	fContext;
	uint8*				fData;
	size_t				fLength;
	uint64				fBlockIndex;
	size_t				fJobBlocks;
};

class DecryptTask : public CryptTask {
public:
	DecryptTask(TaskCryptContext& context, uint8* data, size_t length,
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
	EncryptTask(TaskCryptContext& context, uint8* data, size_t length,
		uint64 blockIndex)
		:
		CryptTask(context, data, length, blockIndex)
	{
	}

protected:
	virtual CryptJob* CreateJob(int32 id);
};


void init_crypt_tasks();
void uninit_crypt_tasks();


#endif	// TASKS_H
