/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef LOGIN_WINDOW_H
#define LOGIN_WINDOW_H


#include <Window.h>

class BButton;
class BMessageRunner;
class BTextControl;
class PaneSwitch;


class LoginWindow : public BWindow {
public:
	LoginWindow(BMessage& settings);
	virtual ~LoginWindow();

	virtual void MessageReceived(BMessage* message);

private:
	bool _FindRegistered(const char* file, char* buffer, size_t bufferSize);
	status_t _MountEncrypted(const char* file, const char* mountAt);
	void _MountAll();
	void _LaunchLoginScript();
	status_t _CheckPassword(const char* password);
	void _Bounce(BMessage* message = NULL);

	BMessage&		fSettings;
	BTextControl*	fPasswordControl;
	BButton*		fLoginButton;
	BButton*		fRestartButton;
	BMessageRunner*	fRunner;
	int32			fFailureCount;
	PaneSwitch*		fMoreSwitch;
};

#endif	// LOGIN_WINDOW_H
