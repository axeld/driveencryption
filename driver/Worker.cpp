/*
 * Copyright 2012-2022, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "Worker.h"

#include <util/AutoLock.h>

#include <new>


static int32 sNextID;


Task::Task()
	:
	fFinished(false),
	fPending(0)
{
	mutex_init(&fLock, "task");
	fFinishCondition.Init(this, "task finished");
}


Task::~Task()
{
	mutex_lock(&fLock);
	mutex_destroy(&fLock);
}


Job*
Task::NextJob(int32 id)
{
	Job* job = CreateNextJob(id);

	MutexLocker locker(fLock);
	if (job != NULL)
		fPending++;

	return job;
}


void
Task::TaskDone()
{
	MutexLocker locker(fLock);

	fFinished = true;
	if (fPending == 0)
		fFinishCondition.NotifyOne();
}


void
Task::JobDone(Job* job)
{
	MutexLocker locker(fLock);

	if (--fPending == 0 && fFinished)
		fFinishCondition.NotifyOne();
}


void
Task::Wait()
{
	while (true) {
		MutexLocker locker(fLock);

		if (fFinished && !fPending)
			return;

		ConditionVariableEntry entry;
		fFinishCondition.Add(&entry);
		locker.Unlock();

		entry.Wait();
	}
}


// #pragma mark -


Worker::Worker()
	:
	fThreads(NULL),
	fThreadCount(0)
{
	mutex_init(&fLock, "worker");
	MutexLocker t(fLock);
	fCondition.Init(this, "work wait");

	system_info info;
	if (get_system_info(&info) == B_OK)
		fThreadCount = min_c(31, info.cpu_count - 1);
	if (fThreadCount < 0)
		fThreadCount = 0;
}


Worker::~Worker()
{
	fCondition.NotifyAll(B_ERROR);
	mutex_lock(&fLock);
	mutex_destroy(&fLock);

	if (fThreads != NULL) {
		for (int32 i = 0; i < fThreadCount; i++) {
			wait_for_thread(fThreads[i], NULL);
		}

		delete[] fThreads;
	}
}


status_t
Worker::Init()
{
	if (fThreadCount > 0) {
		fThreads = new(std::nothrow) thread_id[fThreadCount];
		if (fThreads == NULL)
			return B_NO_MEMORY;

		for (int32 i = 0; i < fThreadCount; i++) {
			fThreads[i] = spawn_kernel_thread(&_Worker, "worker",
				B_NORMAL_PRIORITY, this);
			resume_thread(fThreads[i]);
		}
	}
	return B_OK;
}


void
Worker::AddTask(Task& task)
{
	MutexLocker locker(fLock);
	fTasks.Add(&task);

	fCondition.NotifyAll();
}


void
Worker::WaitFor(Task& task)
{
	_Work(0);
	task.Wait();
}


/*static*/ status_t
Worker::_Worker(void* self)
{
	((Worker*)self)->_Worker();
	return B_OK;
}


void
Worker::_Worker()
{
	int32 id = 1 + atomic_add(&sNextID, 1);

	while (true) {
		MutexLocker locker(fLock);

		if (fTasks.IsEmpty()) {
			ConditionVariableEntry entry;
			fCondition.Add(&entry);
			locker.Unlock();

			status_t status = entry.Wait();
			if (status != B_OK)
				break;
		} else
			locker.Unlock();

		_Work(id);
	}
}


void
Worker::_Work(int32 id)
{
	while (true) {
		MutexLocker locker(fLock);

		Task* task = fTasks.First();
		if (task == NULL)
			return;

		Job* job = task->NextJob(id);
		if (job == NULL) {
			fTasks.Remove(task);
			task->TaskDone();
			return;
		}

		locker.Unlock();

		job->Do();
		task->JobDone(job);
	}
}
