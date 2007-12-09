/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef PASSWORD_WINDOW_H
#define PASSWORD_WINDOW_H


#include <Window.h>

class BButton;
class BMessageRunner;
class BTextControl;


class PasswordWindow : public BWindow {
public:
	PasswordWindow(const char* title, const char* text, BMessenger target,
		BMessage* message);
	virtual ~PasswordWindow();

	virtual void MessageReceived(BMessage* message);
	virtual void DispatchMessage(BMessage* message, BHandler* target);

private:
	void _Bounce(BMessage* message = NULL);

	BMessenger		fTarget;
	BMessage*		fMessage;
	BTextControl*	fPasswordControl;
	BButton*		fOkButton;
	BMessageRunner*	fRunner;
};

#endif	// PASSWORD_WINDOW_H
