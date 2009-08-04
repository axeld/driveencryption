/*
 * Copyright 2007-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "PasswordWindow.h"

#include <Alert.h>
#include <Button.h>
#include <MessageRunner.h>
#include <TextControl.h>

#include <string.h>


const uint32 kMsgEntered = 'ente';
const uint32 kMsgBounce = 'boun';
const uint32 kMsgChanged = 'chan';


PasswordWindow::PasswordWindow(const char* title, const char* text,
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
	if (text != NULL) {
		BRect textViewRect(rect.InsetByCopy(3, 0));

		BTextView* textView = new BTextView(textViewRect, "text",
			textViewRect.OffsetByCopy(B_ORIGIN),
			B_FOLLOW_LEFT | B_FOLLOW_TOP, B_WILL_DRAW);
		textView->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
		textView->SetText(text, strlen(text));
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
	}

	fPasswordControl = new BTextControl(rect, NULL, "Password:", "",
		new BMessage(kMsgEntered), B_FOLLOW_LEFT_RIGHT);
	fPasswordControl->SetDivider(
		fPasswordControl->StringWidth(fPasswordControl->Label()) + 8.0f);
	fPasswordControl->SetModificationMessage(new BMessage(kMsgChanged));
	fPasswordControl->TextView()->HideTyping(true);
	top->AddChild(fPasswordControl);

	rect.top += fPasswordControl->Bounds().Height() + 10;
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
		+ fPasswordControl->Frame().bottom + 20);

	MoveTo(BAlert::AlertPosition(Frame().Width(), Frame().Height()));

	fPasswordControl->MakeFocus(true);
}


PasswordWindow::~PasswordWindow()
{
	delete fRunner;
	delete fMessage;
}


void
PasswordWindow::_Bounce(BMessage* message)
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
PasswordWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgChanged:
			fOkButton->SetEnabled(fPasswordControl->TextView()->TextLength() > 0);
			break;

		case kMsgEntered:
		{
			if (fRunner != NULL)
				break;

			if (fMessage->ReplaceString("password", fPasswordControl->Text()) != B_OK)
				fMessage->AddString("password", fPasswordControl->Text());

			BMessage reply;
			fTarget.SendMessage(fMessage, &reply);

			int32 error;
			if (reply.FindInt32("error", &error) == B_OK && error != B_OK) {
				fPasswordControl->TextView()->SelectAll();
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
PasswordWindow::DispatchMessage(BMessage* message, BHandler* target)
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

