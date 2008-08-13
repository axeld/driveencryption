/*
 * Copyright 2007-2008, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef CHANGE_PASSWORD_WINDOW_H
#define CHANGE_PASSWORD_WINDOW_H


#include <Messenger.h>
#include <Window.h>

class BButton;
class BMessageRunner;
class BStringView;
class BTextControl;


class ChangePasswordWindow : public BWindow {
public:
	ChangePasswordWindow(const char* title, bool hadPassword, BMessenger target,
		BMessage* message);
	virtual ~ChangePasswordWindow();

	virtual void MessageReceived(BMessage* message);
	virtual void DispatchMessage(BMessage* message, BHandler* target);

private:
	void _Bounce(BMessage* message = NULL);

	BMessenger		fTarget;
	BMessage*		fMessage;
	BTextControl*	fOldPasswordControl;
	BTextControl*	fNewPasswordControl;
	BTextControl*	fReenterPasswordControl;
	BStringView*	fErrorView;
	BButton*		fOkButton;
	BMessageRunner*	fRunner;
};

#endif	// CHANGE_PASSWORD_WINDOW_H
