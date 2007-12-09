/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */


#include <Alert.h>
#include <Application.h>
#include <File.h>
#include <FindDirectory.h>
#include <Path.h>
#include <TextView.h>

#include "LoginWindow.h"


class Login : public BApplication {
public:
	Login();
	virtual ~Login();

	virtual void ReadyToRun();
	virtual void AboutRequested();

private:
	status_t _OpenSettings(BFile& file, int32 mode);
	void _LoadSettings();

	BMessage	fSettings;
};


Login::Login()
	: BApplication("application/x-vnd.pinc-Login")
{
}


Login::~Login()
{
}


status_t
Login::_OpenSettings(BFile& file, int32 mode)
{
	BPath path;
	if (find_directory(B_USER_SETTINGS_DIRECTORY, &path) != B_OK)
		return B_ERROR;

	path.Append("pinc.DriveEncryption settings");

	return file.SetTo(path.Path(), mode);
}


void
Login::_LoadSettings()
{
	BFile file;
	if (_OpenSettings(file, B_READ_ONLY) != B_OK)
		return;

	fSettings.Unflatten(&file);
}


void
Login::ReadyToRun()
{
	_LoadSettings();

	BWindow* window = new LoginWindow(fSettings);
	window->Show();
}


void
Login::AboutRequested()
{
	BAlert *alert = new BAlert("about", "Login\n"
		"\twritten by Axel Dörfler\n"
		"\tCopyright 2007, pinc Software.\n\n", "Ok");
	BTextView *view = alert->TextView();
	BFont font;

	view->SetStylable(true);

	view->GetFont(&font);
	font.SetSize(font.Size() * 1.8);
	font.SetFace(B_BOLD_FACE);
	view->SetFontAndColor(0, 5, &font);

	alert->Go();
}


//	#pragma mark -


int
main(int argc, char **argv)
{
	Login app;

	app.Run();
	return 0;
}
