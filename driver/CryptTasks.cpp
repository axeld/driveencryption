/*
 * Copyright 2008-2025, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "CryptTasks.h"

#include "Worker.h"


#ifndef DPRINTF
#	ifdef USER_MODE
#		define DPRINTF(...) printf(__VA_ARGS__)
#	else
#		define DPRINTF(...) dprintf(__VA_ARGS__)
#	endif
#endif

//#define TRACE_CRYPT_TASKS
#ifdef TRACE_CRYPT_TASKS
#	define TRACE(...)	DPRINTF(__VA_ARGS__)
#else
#	define TRACE(...)	;
#endif


static int32 sThreadCount;


class CryptJob : public Job {
public:
	CryptJob()
		:
		fEncryptionMode(NULL),
		fThreadContext(NULL),
		fData(NULL),
		fLength(0),
		fBlockIndex(0)
	{
	}

	void SetTo(EncryptionMode* mode, ThreadContext* context, uint8* data,
		size_t length, uint64 blockIndex)
	{
		fEncryptionMode = mode;
		fThreadContext = context;
		fData = data;
		fLength = length;
		fBlockIndex = blockIndex;
	}

protected:
	EncryptionMode*	fEncryptionMode;
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
		fEncryptionMode->DecryptBlock(*fThreadContext, fData, fLength,
			fBlockIndex);
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
		fEncryptionMode->EncryptBlock(*fThreadContext, fData, fLength,
			fBlockIndex);
	}
};


//	#pramga mark - TaskCryptContext


TaskCryptContext::TaskCryptContext()
	:
	fEncryptJobs(NULL),
	fDecryptJobs(NULL)
{
	fThreadCount = sThreadCount;
}


TaskCryptContext::~TaskCryptContext()
{
	delete[] fEncryptJobs;
	delete[] fDecryptJobs;
}


/*virtual*/ status_t
TaskCryptContext::_InitThreadContext(ThreadContext& threadContext)
{
	status_t status = CryptContext::_InitThreadContext(threadContext);
	if (status != B_OK)
		return status;

	fEncryptJobs = new(std::nothrow) EncryptJob[fThreadCount];
	fDecryptJobs = new(std::nothrow) DecryptJob[fThreadCount];
	if (fEncryptJobs == NULL || fDecryptJobs == NULL)
		return B_NO_MEMORY;

	return B_OK;
}


//	#pragma mark - CryptTask


CryptTask::CryptTask(TaskCryptContext& context, uint8* data, size_t length,
	uint64 blockIndex)
	:
	fContext(context),
	fData(data),
	fLength(length),
	fBlockIndex(blockIndex)
{
	fJobBlocks = ((fLength / BLOCK_SIZE) + sThreadCount - 1) / sThreadCount;
	if (fJobBlocks < 1)
		fJobBlocks = 1;
}


EncryptJob*
CryptTask::EncryptJobs(int32 id)
{
	return &fContext.fEncryptJobs[id];
}


DecryptJob*
CryptTask::DecryptJobs(int32 id)
{
	return &fContext.fDecryptJobs[id];
}


Job*
CryptTask::CreateNextJob(int32 id)
{
	if (IsDone())
		return NULL;

	CryptJob* job = CreateJob(id);
	if (!_PrepareJob(job, id))
		return NULL;

	return job;
}


bool
CryptTask::_PrepareJob(CryptJob* job, int32 id)
{
	size_t bytes = min_c(fJobBlocks * BLOCK_SIZE, fLength);
	job->SetTo(Mode(), fContext.fThreadContexts[id], fData, bytes, fBlockIndex);
	fData += bytes;
	fLength -= bytes;
	fBlockIndex += fJobBlocks;
	return true;
}


//	#pragma mark - DecryptTask


CryptJob*
DecryptTask::CreateJob(int32 id)
{
	return DecryptJobs(id);
}


//	#pragma mark - EncryptTask


CryptJob*
EncryptTask::CreateJob(int32 id)
{
	return EncryptJobs(id);
}


//	#pragma mark -


void
init_crypt_tasks()
{
	system_info info;
	if (get_system_info(&info) == B_OK)
		sThreadCount = min_c(32, info.cpu_count);
	if (sThreadCount == 0)
		sThreadCount = 1;
}


void
uninit_crypt_tasks()
{
}
