/*
 * Copyright 2012-2020, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef WORKER_H
#define WORKER_H


#include "Worker.h"

#include <condition_variable.h>
#include <lock.h>

#include <KernelExport.h>


class Job {
public:
								Job() {}
	virtual						~Job() {}

	virtual	void				Do() = 0;
};

class Task : public DoublyLinkedListLinkImpl<Task> {
public:
								Task();
	virtual						~Task();

			Job*				NextJob(int32 id);
			void				TaskDone();

			void				JobDone(Job* job);
			void				Wait();

protected:
	virtual	Job*				CreateNextJob(int32 id) = 0;

private:
			mutex				fLock;
			ConditionVariable	fFinishCondition;
			vint32				fPending;
			bool				fFinished;
};

typedef DoublyLinkedList<Task> TaskList;


class Worker {
public:
								Worker();
	virtual						~Worker();

			status_t			Init();
			int32				CountThreads() const { return fThreadCount; }

			void				AddTask(Task& task);
			void				WaitFor(Task& task);

private:
	static	status_t			_Worker(void* self);
			void				_Worker();
			void				_Work(int32 id);

private:
			thread_id*			fThreads;
			int32				fThreadCount;
			mutex				fLock;
			ConditionVariable	fCondition;
			TaskList			fTasks;
};


#endif	// WORKER_H
