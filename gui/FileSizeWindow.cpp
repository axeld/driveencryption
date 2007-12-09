/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */


#include "FileSizeWindow.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <Alert.h>
#include <Beep.h>
#include <Button.h>
#include <MessageRunner.h>
#include <Slider.h>
#include <TextControl.h>


const uint32 kMsgEntered = 'ente';
const uint32 kMsgChanged = 'chan';

const off_t kGigaByte = 1024LL * 1024 * 1024;
const off_t kMegaByte = 1024LL * 1024;


FileSizeWindow::FileSizeWindow(const char* title, const char* text, off_t min,
		off_t max, BMessenger target, BMessage* message)
	: BWindow(BRect(100, 100, 400, 300), title, B_MODAL_WINDOW_LOOK,
		B_MODAL_APP_WINDOW_FEEL, B_NOT_V_RESIZABLE | B_ASYNCHRONOUS_CONTROLS),
	fTarget(target),
	fMessage(message),
	fMinimum(min),
	fMaximum(max)
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
			B_FOLLOW_LEFT_RIGHT | B_FOLLOW_TOP, B_WILL_DRAW);
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

	fSizeControl = new BTextControl(rect, NULL, "File Size:",
		_Size(min).String(), NULL, B_FOLLOW_LEFT_RIGHT);
	fSizeControl->SetDivider(
		fSizeControl->StringWidth(fSizeControl->Label()) + 8.0f);
	fSizeControl->SetModificationMessage(new BMessage(kMsgChanged));
	top->AddChild(fSizeControl);

	if (min > kGigaByte || max > 1024 * kGigaByte)
		fDivider = kGigaByte;
	else
		fDivider = kMegaByte;

	rect.top += fSizeControl->Bounds().Height() + 10;
	fSlider = new BSlider(rect, "slider", NULL, NULL, min / fDivider,
		max / fDivider, B_BLOCK_THUMB, B_FOLLOW_LEFT_RIGHT);
	fSlider->SetLimitLabels(_Size(min).String(), _Size(max).String());
	fSlider->SetModificationMessage(new BMessage(kMsgChanged));
	fSlider->ResizeToPreferred();
	top->AddChild(fSlider);

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
	top->AddChild(fOkButton);

	ResizeTo(300, cancelButton->Bounds().Height()
		+ fSlider->Frame().bottom + 20);

	MoveTo(BAlert::AlertPosition(Frame().Width(), Frame().Height()));

	fSizeControl->MakeFocus(true);
}


FileSizeWindow::~FileSizeWindow()
{
	delete fMessage;
}


BString
FileSizeWindow::_Size(off_t bytes)
{
	char string[64];

	if (bytes < 1024)
		sprintf(string, "%Ld bytes", bytes);
	else {
		char *units[] = {"KB", "MB", "GB", "TB", NULL};
		double size = bytes;
		int32 i = -1;

		do {
			size /= 1024.0;
			i++;
		} while (size >= 1024 && units[i + 1]);

		sprintf(string, "%.1f %s", size, units[i]);
	}

	return BString(string);
}


off_t
FileSizeWindow::_ParseSize(const char* string)
{
	char* end;
	double size = strtod(string, &end);
	off_t bytes = off_t(size * 10.0);
	if (size == 0.0) {
		// for hex numbers
		bytes = strtoll(string, &end, 0);
		size = (double)bytes;
	}

	if (end == NULL)
		return bytes;

	while (isspace(end[0])) {
		end++;
	}

	switch (end[0]) {
		case 'M':
		case 'm':
			return off_t(size * kMegaByte);
		case 'G':
		case 'g':
			return off_t(size * kGigaByte);
		case 'T':
		case 't':
			return off_t(size * 1024 * kGigaByte);
	}

	return bytes;
}


void
FileSizeWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgEntered:
		{
			size_t size = _ParseSize(fSizeControl->Text());
			if (size == 0) {
				fSizeControl->TextView()->SelectAll();
				fSizeControl->MakeFocus(true);
				beep();
				break;
			}

			if (fMessage->ReplaceInt64("size", size) != B_OK)
				fMessage->AddInt64("size", size);

			fTarget.SendMessage(fMessage);
			PostMessage(B_QUIT_REQUESTED);
			break;
		}

		case kMsgChanged:
		{
			void* source;
			if (message->FindPointer("source", &source) != B_OK)
				break;

			if (source == fSlider) {
				// update text control
				off_t size = fSlider->Value() * fDivider;
				if (size < fMinimum)
					size = fMinimum;
				else if (size > fMaximum)
					size = fMaximum;

				message = new BMessage(*fSizeControl->ModificationMessage());
				fSizeControl->SetModificationMessage(NULL);
				fSizeControl->SetText(_Size(size).String());
				fSizeControl->SetModificationMessage(message);
			} else {
				// update slider
				off_t size = _ParseSize(fSizeControl->Text());
				if (size < fMinimum)
					size = fMinimum;
				else if (size > fMaximum)
					size = fMaximum;

				message = new BMessage(*fSlider->ModificationMessage());
				fSlider->SetModificationMessage(NULL);
				fSlider->SetValue(size / fDivider);
				fSlider->SetModificationMessage(message);
			}
			break;
		}

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
FileSizeWindow::DispatchMessage(BMessage* message, BHandler* target)
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

