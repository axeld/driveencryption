/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */


#include "LoginWindow.h"

#include <stdlib.h>
#include <unistd.h>

#include <Alert.h>
#include <Application.h>
#include <Button.h>
#include <FindDirectory.h>
#include <MessageRunner.h>
#include <Path.h>
#include <StringView.h>
#include <TextControl.h>

#include "encrypted_drive.h"

#include "mount_support.h"
#include "PaneSwitch.h"


const uint32 kMsgEntered = 'ente';
const uint32 kMsgBounce = 'boun';
const uint32 kMsgWaited = 'wait';
const uint32 kMsgMoreSwitched = 'more';
const uint32 kMsgRestart = 'rstt';
const uint32 kMsgShutdown = 'shut';
const uint32 kMsgChanged = 'chan';


LoginWindow::LoginWindow(BMessage& settings)
	: BWindow(BRect(100, 100, 400, 300), "Login", B_MODAL_WINDOW_LOOK,
		B_MODAL_ALL_WINDOW_FEEL, B_NOT_V_RESIZABLE | B_ASYNCHRONOUS_CONTROLS),
	fSettings(settings),
	fRunner(NULL),
	fFailureCount(0)
{
	BRect rect = Bounds();
	BView* top = new BView(rect, "top", B_FOLLOW_ALL, 0);
	top->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
	AddChild(top);

	rect = top->Bounds().InsetByCopy(10, 10);
	
	BString text = "Welcome, ";
	const char* login = getlogin();
	if (login == NULL || !login[0])
		login = "Stranger";
	text << login << "!";

	BRect textViewRect(rect.InsetByCopy(3, 0));

	BTextView* textView = new BTextView(textViewRect, "text",
		textViewRect.OffsetByCopy(B_ORIGIN),
		B_FOLLOW_LEFT | B_FOLLOW_TOP, B_WILL_DRAW);
	textView->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
	textView->SetStylable(true);
	textView->SetText(text.String(), text.Length());
	textView->SetFontAndColor(0, textView->TextLength(), be_bold_font);
	textView->MakeEditable(false);
	textView->MakeSelectable(false);
	textView->SetWordWrap(true);
	top->AddChild(textView);

	// Now resize the TextView vertically so that all the text is visible
	float textHeight = textView->TextHeight(0, textView->CountLines());
	textViewRect.OffsetTo(0, 0);
	textHeight -= textViewRect.Height();
	textView->ResizeBy(0, textHeight);
	textViewRect.bottom += textHeight;
	textView->SetTextRect(textViewRect);

	rect.top += textViewRect.Height() + 10;
	fPasswordControl = new BTextControl(rect, NULL, "Password:", "",
		new BMessage(kMsgEntered), B_FOLLOW_LEFT_RIGHT);
	fPasswordControl->SetDivider(
		fPasswordControl->StringWidth(fPasswordControl->Label()) + 8.0f);
	fPasswordControl->SetModificationMessage(new BMessage(kMsgChanged));
	fPasswordControl->TextView()->HideTyping(true);
	top->AddChild(fPasswordControl);

	rect.top += fPasswordControl->Bounds().Height() + 10;
	fLoginButton = new BButton(rect, "login", "Login", new BMessage(kMsgEntered),
		B_FOLLOW_RIGHT | B_FOLLOW_TOP);
	fLoginButton->ResizeToPreferred();
	fLoginButton->MoveTo(rect.right - fLoginButton->Bounds().Width(),
		rect.top);
	fLoginButton->SetEnabled(false);
	top->AddChild(fLoginButton);

	rect.right = rect.left + 20;
	rect.top += 7;
	rect.bottom = rect.top + 20;
	fMoreSwitch = new PaneSwitch(rect, NULL);
	fMoreSwitch->SetValue(kPaneSwitchClosed);
	fMoreSwitch->SetMessage(new BMessage(kMsgMoreSwitched));
	fMoreSwitch->SetViewColor(255, 0, 0);
	top->AddChild(fMoreSwitch);

	BStringView* stringView = new BStringView(rect, "more",
		"More" B_UTF8_ELLIPSIS);
	BFont font;
	font.SetSize(10);
	font.SetFace(B_ITALIC_FACE);
	stringView->SetFont(&font);
	stringView->ResizeToPreferred();
	stringView->MoveBy(20, 3);
	top->AddChild(stringView);

	ResizeTo(300, fLoginButton->Bounds().Height()
		+ fPasswordControl->Frame().bottom + 20);

	rect.top = Frame().Height();
	fRestartButton = new BButton(rect, "restart", "Restart",
		new BMessage(kMsgRestart), B_FOLLOW_LEFT | B_FOLLOW_TOP);
	fRestartButton->ResizeToPreferred();
	fRestartButton->Hide();
	top->AddChild(fRestartButton);

	BButton* shutdownButton = new BButton(rect, "shutdown", "Shutdown",
		new BMessage(kMsgShutdown), B_FOLLOW_LEFT | B_FOLLOW_TOP);
	shutdownButton->ResizeToPreferred();
	shutdownButton->MoveBy(fRestartButton->Bounds().Width() + 10, 0);
	top->AddChild(shutdownButton);

	MoveTo(BAlert::AlertPosition(Frame().Width(), Frame().Height()));

	fPasswordControl->MakeFocus(true);
	fLoginButton->MakeDefault(true);
}


LoginWindow::~LoginWindow()
{
	delete fRunner;
}


void
LoginWindow::_Bounce(BMessage* message)
{
	int32 count = 0;
	float diff = 0;
	if (message != NULL && message->what == kMsgBounce) {
		message->FindInt32("count", &count);
		message->FindFloat("diff", &diff);
	}

	MoveBy(-diff, 0);

	const int32 kLast = 10;
	if (count > 0)
		diff = (10 - count) * ((count & 1) != 0 ? -1 : 1);
	else
		diff = 10;

	if (count < kLast)
		MoveBy(diff, 0);

	BMessage bounce(kMsgBounce);
	bounce.AddInt32("count", count + 1);
	bounce.AddFloat("diff", diff);

	delete fRunner;

	if (count < kLast)
		fRunner = new BMessageRunner(this, &bounce, 10000LL, 1);
	else
		fRunner = NULL;

	if (fFailureCount >= 3) {
		fPasswordControl->SetEnabled(false);
		fLoginButton->SetEnabled(false);

		if (fRunner == NULL) {
			BMessage wait(kMsgWaited);
			fRunner = new BMessageRunner(this, &wait,
				(fFailureCount + 2) * 1000000LL, 1);
				// wait for 5 or more seconds
		}
	}
}


bool
LoginWindow::_FindRegistered(const char* file, char* buffer, size_t bufferSize)
{
	for (int32 i = 0; i < 10; i++) {
		char path[B_PATH_NAME_LENGTH];
		snprintf(path, B_PATH_NAME_LENGTH, "%s/%ld", ENCRYPTED_DRIVE_DIRECTORY,
			i);

		// open the device
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		encrypted_drive_info info;
		info.magic = ENCRYPTED_DRIVE_MAGIC;
		info.drive_info_size = sizeof(info);

		int error = ioctl(fd, ENCRYPTED_DRIVE_GET_INFO, &info);
		close(fd);

		if (error == 0 && !strcmp(file, info.file_name)) {
			strncpy(buffer, info.device_name, bufferSize);
			buffer[bufferSize - 1] = '\0';
			return true;
		}
	}

	return false;
}


status_t
LoginWindow::_MountEncrypted(const char* file, const char* mountAt)
{
	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open control device: %s\n",
				strerror(errno));
		return errno;
	}

	// set up the info
	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);
	info.key = (const uint8*)fPasswordControl->Text();
	info.key_length = fPasswordControl->TextView()->TextLength();
	info.random_data = NULL;
	info.random_length = 0;
	info.read_only = false;
	strcpy(info.file_name, file);

	// issue the ioctl
	status_t error = B_OK;
	if (ioctl(fd, ENCRYPTED_DRIVE_REGISTER_FILE, &info) != 0) {
		close(fd);

		if (!_FindRegistered(file, info.device_name,
				sizeof(info.device_name))) {
			fprintf(stderr, "Registering of \"%s\" failed.", file);
			return errno;
		}
	}

	return mount_device(info.device_name, mountAt);
}


void
LoginWindow::_MountAll()
{
	BMessage drives;
	if (fSettings.FindMessage("drives", &drives) == B_OK) {
		const char* file;
		for (int32 i = 0; drives.FindString("file", i, &file) == B_OK; i++) {
			bool autoMount = drives.FindBool("auto mount");
			const char* mountAt = drives.FindString("mount at");

			if (autoMount)
				_MountEncrypted(file, mountAt);
		}
	}
}


void
LoginWindow::_LaunchLoginScript()
{
	BPath scriptPath;
	if (find_directory(B_USER_BOOT_DIRECTORY, &scriptPath) != B_OK)
		return;

	scriptPath.Append("LoginScript");

	BString command("/bin/sh ");
	command << scriptPath.Path() << " &";
	system(command.String());
}


status_t
LoginWindow::_CheckPassword(const char* password)
{
	const uint8* data;
	ssize_t bufferLength;
	if (fSettings.FindData("password", B_RAW_TYPE, (const void**)&data,
			&bufferLength) != B_OK
		|| bufferLength < ENCRYPTED_DRIVE_SALT_SIZE) {
		// there is no valid password, accept only the empty password
		if (password[0])
			return B_PERMISSION_DENIED;

		return B_OK;
	}
	uint8* buffer = (uint8*)malloc(bufferLength);
	if (buffer == NULL)
		return B_NO_MEMORY;

	memcpy(buffer, data, bufferLength);

	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0)
		return errno;

	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);

	// check if this password decrypts the old one

	info.key = (const uint8*)password;
	info.key_length = strlen(password);
	info.random_data = buffer;
	info.random_length = bufferLength;
	info.buffer = buffer + ENCRYPTED_DRIVE_SALT_SIZE;
	info.buffer_length = bufferLength - ENCRYPTED_DRIVE_SALT_SIZE;

	if (ioctl(fd, ENCRYPTED_DRIVE_DECRYPT_BUFFER, &info) != 0) {
		close(fd);
		return errno;
	}

	close(fd);

	return strcmp((const char*)buffer + ENCRYPTED_DRIVE_SALT_SIZE,
		password) ? B_PERMISSION_DENIED : B_OK;
}


void
LoginWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgChanged:
			fLoginButton->SetEnabled(
				fPasswordControl->TextView()->TextLength() > 0);
			break;

		case kMsgEntered:
		{
			if (fRunner != NULL)
				break;

			if (_CheckPassword(fPasswordControl->Text()) < B_OK) {
				fPasswordControl->TextView()->SelectAll();
				fFailureCount++;
				_Bounce();
			} else {
				Hide();
				_MountAll();
				_LaunchLoginScript();
				be_app->PostMessage(B_QUIT_REQUESTED);
			}
			break;
		}

		case kMsgBounce:
			_Bounce(message);
			break;

		case kMsgWaited:
			fPasswordControl->SetEnabled(true);
			fLoginButton->SetEnabled(true);

			delete fRunner;
			fRunner = NULL;
			break;

		case kMsgMoreSwitched:
			if (fRestartButton->IsHidden()) {
				fRestartButton->Show();
				ResizeBy(0, fRestartButton->Bounds().Height() + 10);
				fMoreSwitch->SetValue(kPaneSwitchOpen);
			} else {
				ResizeBy(0, -fRestartButton->Bounds().Height() - 10);
				fRestartButton->Hide();
				fMoreSwitch->SetValue(kPaneSwitchClosed);
			}
			fMoreSwitch->Invalidate();
			break;

		case kMsgRestart:
		{
			BMessenger roster("application/x-vnd.Be-ROST");
			roster.SendMessage(302);
				// Taken from Deskbar
			break;
		}

		case kMsgShutdown:
		{
			BMessenger roster("application/x-vnd.Be-ROST");
			roster.SendMessage(301);
				// Taken from Deskbar
			break;
		}

		default:
			BWindow::MessageReceived(message);
			break;
	}
}

