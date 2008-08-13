/*
 * Copyright 2007-2008, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef FILE_SIZE_WINDOW_H
#define FILE_SIZE_WINDOW_H


#include <Messenger.h>
#include <Window.h>

class BButton;
class BMessageRunner;
class BSlider;
class BTextControl;


class FileSizeWindow : public BWindow {
public:
	FileSizeWindow(const char* title, const char* text, off_t min, off_t max,
		BMessenger target, BMessage* message);
	virtual ~FileSizeWindow();

	virtual void MessageReceived(BMessage* message);
	virtual void DispatchMessage(BMessage* message, BHandler* target);

private:
	BString _Size(off_t);
	off_t _ParseSize(const char* string);

	BMessenger		fTarget;
	BMessage*		fMessage;
	BTextControl*	fSizeControl;
	BSlider*		fSlider;
	off_t			fMinimum;
	off_t			fMaximum;
	off_t			fDivider;
	BButton*		fOkButton;
};

#endif	// FILE_SIZE_WINDOW_H
