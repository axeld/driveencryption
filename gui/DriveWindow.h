/*
 * Copyright 2007, Axel Dörfler, axeld@pinc-software.de. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef DRIVE_WINDOW_H
#define DRIVE_WINDOW_H


#include <Window.h>
#include <Entry.h>

class BFilePanel;
class BMenu;
class DriveListView;
class DriveRow;
struct encrypted_drive_info;


class DriveWindow : public BWindow {
public:
	DriveWindow(const BMessage& settings);
	virtual ~DriveWindow();

	virtual void MessageReceived(BMessage *message);
	virtual bool QuitRequested();

private:
	void _Error(const char* format, ...);
	status_t _SetPassword(BMessage* message);
	void _CheckAuthorization(entry_ref& ref, bool mount);
	void _RemoveFile(DriveRow* row);
	void _MountFile(DriveRow* row);
	void _CreateFile(BMessage* message);
	DriveRow* _UpdateOrAddRow(encrypted_drive_info& info);
	void _InitializeFile(BMessage* message);
	status_t _AddFile(BMessage* message, DriveRow** _row);
	void _RefsReceived(BMessage* refs);
	void _SaveRequested(BMessage* refs);
	bool _IsMounted(BPath& path);
	void _CollectDevices(BMenu *menu, uint32 what, BEntry *startEntry = NULL);

	BFilePanel*		fOpenPanel;
	BFilePanel*		fSavePanel;
	DriveListView*	fListView;
	uint8*			fOldPassword;
	uint32			fOldPasswordLength;
	bool			fPasswordChanged;
};

#endif	/* DRIVE_WINDOW_H */
