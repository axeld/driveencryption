/*
 * Copyright 2007-2009, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "DriveEncryption.h"

#include <Alert.h>
#include <Application.h>
#include <File.h>
#include <FindDirectory.h>
#include <Path.h>
#include <TextView.h>

#include <string.h>

#include "DriveWindow.h"
#include "encrypted_drive.h"


class DriveEncryption : public BApplication {
public:
	DriveEncryption();
	virtual ~DriveEncryption();

	virtual void ReadyToRun();
	virtual void AboutRequested();
	virtual void RefsReceived(BMessage* refs);
	virtual void MessageReceived(BMessage* message);

private:
	status_t _OpenSettings(BFile& file, int32 mode);
	void _LoadSettings();
	void _SaveSettings();
	void _UpdateSettingsFrom(BMessage* message);
	bool _TestForDriver();

	BMessenger	fWindowMessenger;
	BMessage	fSettings;
	bool		fSettingsUpdated;
};


DriveEncryption::DriveEncryption()
	: BApplication("application/x-vnd.pinc-DriveEncryption"),
	fSettingsUpdated(false)
{
}


DriveEncryption::~DriveEncryption()
{
	_SaveSettings();
}


status_t
DriveEncryption::_OpenSettings(BFile& file, int32 mode)
{
	BPath path;
	if (find_directory(B_USER_SETTINGS_DIRECTORY, &path) != B_OK)
		return B_ERROR;

	path.Append("pinc.DriveEncryption settings");

	return file.SetTo(path.Path(), mode);
}


void
DriveEncryption::_LoadSettings()
{
	BFile file;
	if (_OpenSettings(file, B_READ_ONLY) != B_OK)
		return;

	fSettings.Unflatten(&file);
}


void
DriveEncryption::_SaveSettings()
{
	if (!fSettingsUpdated)
		return;

	BFile file;
	if (_OpenSettings(file, B_CREATE_FILE | B_WRITE_ONLY) != B_OK)
		return;

	fSettings.Flatten(&file);
}


void
DriveEncryption::_UpdateSettingsFrom(BMessage* message)
{
	BRect frame;
	if (message->FindRect("window frame", &frame) == B_OK) {
		BRect previousFrame;
		if (fSettings.FindRect("window frame", &previousFrame) != B_OK
			|| frame != previousFrame) {
			if (fSettings.ReplaceRect("window frame", frame) != B_OK)
				fSettings.AddRect("window frame", frame);
			fSettingsUpdated = true;
		}
	}

	const void* data;
	ssize_t size;
	if (message->FindData("password", B_RAW_TYPE, &data, &size) == B_OK) {
		const void* oldData;
		ssize_t oldSize;
		if (fSettings.FindData("password", B_RAW_TYPE, &oldData,
				&oldSize) != B_OK
			|| size != oldSize || memcmp(oldData, data, size)) {
			if (fSettings.ReplaceData("password", B_RAW_TYPE, data, size)
					!= B_OK)
				fSettings.AddData("password", B_RAW_TYPE, data, size);
			fSettingsUpdated = true;
		}
	}

	BMessage drives;
	if (message->FindMessage("drives", &drives) == B_OK) {
		BMessage previous;
		fSettings.FindMessage("drives", &previous);
		// TODO: compare old and new drives!
		if (!previous.IsEmpty() || !drives.IsEmpty()) {
			if (drives.IsEmpty())
				fSettings.RemoveName("drives");
			else if (fSettings.ReplaceMessage("drives", &drives) != B_OK)
				fSettings.AddMessage("drives", &drives);

			fSettingsUpdated = true;
		}
	}
}


bool
DriveEncryption::_TestForDriver()
{
	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return true;
	}

	BAlert *alert = new BAlert("error",
		"Could not open encrypted control device", "Ok", NULL, NULL,
		B_WIDTH_AS_USUAL, B_STOP_ALERT);
	alert->Go();
		return false;
}


void
DriveEncryption::ReadyToRun()
{
	if (!_TestForDriver()) {
		Quit();
		return;
	}

	_LoadSettings();

	BWindow* window = new DriveWindow(fSettings);
	window->Show();

	fWindowMessenger = BMessenger(window);
}


void
DriveEncryption::AboutRequested()
{
	BAlert *alert = new BAlert("about", "DriveEncryption\n"
		"\twritten by Axel Dörfler\n"
		"\tCopyright 2007-2009, pinc Software.\n\n", "Ok");
	BTextView *view = alert->TextView();
	BFont font;

	view->SetStylable(true);

	view->GetFont(&font);
	font.SetSize(font.Size() * 1.8);
	font.SetFace(B_BOLD_FACE);
	view->SetFontAndColor(0, 15, &font);

	alert->Go();
}


void
DriveEncryption::RefsReceived(BMessage* refs)
{
	fWindowMessenger.SendMessage(refs);
}


void
DriveEncryption::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgSettingsChanged:
			_UpdateSettingsFrom(message);
			break;

		default:
			BApplication::MessageReceived(message);
			break;
	}
}


//	#pragma mark -


int
main(int argc, char **argv)
{
	DriveEncryption app;

	app.Run();
	return 0;
}
