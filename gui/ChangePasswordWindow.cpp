/*
 * Copyright 2007-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "ChangePasswordWindow.h"

#include <Alert.h>
#include <Beep.h>
#include <Button.h>
#include <MessageRunner.h>
#include <StringView.h>
#include <TextControl.h>

#include <string.h>


const uint32 kMsgOldEntered = 'onte';
const uint32 kMsgNewEntered = 'nnte';
const uint32 kMsgEntered = 'ente';
const uint32 kMsgBounce = 'boun';
const uint32 kMsgChanged = 'chan';


ChangePasswordWindow::ChangePasswordWindow(const char* title, bool hadPassword,
		BMessenger target, BMessage* message)
	: BWindow(BRect(100, 100, 400, 300), title, B_MODAL_WINDOW_LOOK,
		B_MODAL_APP_WINDOW_FEEL, B_NOT_V_RESIZABLE | B_ASYNCHRONOUS_CONTROLS),
	fTarget(target),
	fMessage(message),
	fRunner(NULL)
{
	BRect rect = Bounds();
	BView* top = new BView(rect, "top", B_FOLLOW_ALL, 0);
	top->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
	AddChild(top);

	rect = top->Bounds().InsetByCopy(10, 10);
	fOldPasswordControl = new BTextControl(rect, NULL, "Old Password:", "",
		new BMessage(kMsgOldEntered), B_FOLLOW_LEFT_RIGHT);
	fOldPasswordControl->TextView()->HideTyping(true);
	fOldPasswordControl->SetEnabled(hadPassword);
	fOldPasswordControl->SetModificationMessage(new BMessage(kMsgChanged));
	if (!hadPassword)
		fOldPasswordControl->Hide();
	top->AddChild(fOldPasswordControl);

	if (hadPassword)
		rect.top += fOldPasswordControl->Bounds().Height() + 10;
	fNewPasswordControl = new BTextControl(rect, NULL, "New Password:", "",
		new BMessage(kMsgNewEntered), B_FOLLOW_LEFT_RIGHT);
	fNewPasswordControl->TextView()->HideTyping(true);
	fNewPasswordControl->SetModificationMessage(new BMessage(kMsgChanged));
	top->AddChild(fNewPasswordControl);

	rect.top += fNewPasswordControl->Bounds().Height() + 10;
	fReenterPasswordControl = new BTextControl(rect, NULL,
		"Reenter New Password:", "", new BMessage(kMsgEntered),
		B_FOLLOW_LEFT_RIGHT);
	fReenterPasswordControl->TextView()->HideTyping(true);
	fReenterPasswordControl->SetModificationMessage(new BMessage(kMsgChanged));
	top->AddChild(fReenterPasswordControl);

	float width = fReenterPasswordControl->StringWidth(
		fReenterPasswordControl->Label()) + 8.0f;
	fOldPasswordControl->SetDivider(width);
	fNewPasswordControl->SetDivider(width);
	fReenterPasswordControl->SetDivider(width);

	rect.top += fReenterPasswordControl->Bounds().Height() + 10;
	fErrorView = new BStringView(rect, "error", "No error");
	fErrorView->SetHighColor(220, 0, 0);
	fErrorView->SetFont(be_bold_font);
	float height;
	fErrorView->GetPreferredSize(&width, &height);
	fErrorView->ResizeTo(rect.Width(), height);
	fErrorView->SetAlignment(B_ALIGN_CENTER);
	fErrorView->Hide();
	top->AddChild(fErrorView);

	rect.top += fErrorView->Bounds().Height() + 10;
	BButton* cancelButton = new BButton(rect, "cancel", "Cancel",
		new BMessage(B_QUIT_REQUESTED), B_FOLLOW_RIGHT | B_FOLLOW_BOTTOM);
	cancelButton->ResizeToPreferred();
	top->AddChild(cancelButton);

	fOkButton = new BButton(rect, "ok", "Ok", new BMessage(kMsgEntered),
		B_FOLLOW_RIGHT | B_FOLLOW_BOTTOM);
	fOkButton->ResizeToPreferred();
	fOkButton->MoveTo(rect.right - fOkButton->Bounds().Width(),
		rect.bottom - fOkButton->Bounds().Height());
	cancelButton->MoveTo(fOkButton->Frame().left - 10
		- cancelButton->Bounds().Width(), fOkButton->Frame().top);
	fOkButton->MakeDefault(true);
	fOkButton->SetEnabled(false);
	top->AddChild(fOkButton);

	ResizeTo(300, cancelButton->Bounds().Height()
		+ fErrorView->Frame().bottom + 20);

	MoveTo(BAlert::AlertPosition(Frame().Width(), Frame().Height()));

	if (hadPassword)
		fOldPasswordControl->MakeFocus(true);
	else
		fNewPasswordControl->MakeFocus(true);
}


ChangePasswordWindow::~ChangePasswordWindow()
{
	delete fRunner;
	delete fMessage;
}


void
ChangePasswordWindow::_Bounce(BMessage* message)
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
}


void
ChangePasswordWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgOldEntered:
			fNewPasswordControl->MakeFocus(true);
			break;
		case kMsgNewEntered:
			fReenterPasswordControl->MakeFocus(true);
			break;
		case kMsgChanged:
		{
			bool newEmpty = fNewPasswordControl->TextView()->TextLength() == 0;
			bool reenterEmpty = fReenterPasswordControl->TextView()->TextLength() == 0;
			if ((!newEmpty || !reenterEmpty) && !fErrorView->IsHidden())
				fErrorView->Hide();

			bool enabled = !newEmpty && !reenterEmpty;
			if (enabled && fOldPasswordControl->IsEnabled())
				enabled = fOldPasswordControl->TextView()->TextLength() > 0;

			fOkButton->SetEnabled(enabled);
			break;
		}

		case kMsgEntered:
		{
			if (fRunner != NULL)
				break;

			if (fNewPasswordControl->TextView()->TextLength() == 0) {
				beep();
				break;
			}
			if (strcmp(fNewPasswordControl->Text(),
					fReenterPasswordControl->Text())) {
				beep();
				fNewPasswordControl->SetText("");
				fReenterPasswordControl->SetText("");
				fNewPasswordControl->MakeFocus(true);
				fErrorView->SetText("The passwords were different!");
				if (fErrorView->IsHidden())
					fErrorView->Show();
				break;
			}

			if (fMessage->ReplaceString("old password", fOldPasswordControl->Text()) != B_OK)
				fMessage->AddString("old password", fOldPasswordControl->Text());
			if (fMessage->ReplaceString("new password", fNewPasswordControl->Text()) != B_OK)
				fMessage->AddString("new password", fNewPasswordControl->Text());

			BMessage reply;
			fTarget.SendMessage(fMessage, &reply);

			int32 error;
			if (reply.FindInt32("error", &error) == B_OK && error != B_OK) {
				fOldPasswordControl->MakeFocus(true);
				fOldPasswordControl->TextView()->SelectAll();
				_Bounce();
			} else
				PostMessage(B_QUIT_REQUESTED);
			break;
		}

		case kMsgBounce:
			_Bounce(message);
			break;

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
ChangePasswordWindow::DispatchMessage(BMessage* message, BHandler* target)
{
	if (message->what == B_KEY_DOWN) {
		const char *string;
		if (message->FindString("bytes", &string) == B_OK
			&& string[0] == B_ESCAPE) {
			PostMessage(B_QUIT_REQUESTED);
			return;
		}
	}

	return BWindow::DispatchMessage(message, target);
}

