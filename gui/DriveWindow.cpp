/*
 * Copyright 2007-2008, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include "DriveWindow.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <Alert.h>
#include <Application.h>
#include <Button.h>
#include <Directory.h>
#include <FilePanel.h>
#include <fs_info.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Path.h>
#include <Screen.h>
#include <View.h>
#include <Volume.h>

#ifdef __HAIKU__
#	include <fs_volume.h>
#endif

#include "encrypted_drive.h"

#include "ChangePasswordWindow.h"
#include "ColumnListView.h"
#include "ColumnTypes.h"
#include "DriveEncryption.h"
#include "FileSizeWindow.h"
#include "mount_support.h"
#include "PasswordWindow.h"
#include "random.h"


const uint32 kMsgNewFile = 'nwfi';
const uint32 kMsgNewFilePassword = 'nwfp';
const uint32 kMsgCreateFile = 'crfi';
const uint32 kMsgCreateFileSize = 'crfs';
const uint32 kMsgAddFile = 'adfi';
const uint32 kMsgRemoveFile = 'rmfi';
const uint32 kMsgMountFile = 'mnfi';
const uint32 kMsgInitializeFile = 'init';
const uint32 kMsgCheckAuthorization = 'chau';
const uint32 kMsgCheckAuthorizationAndMount = 'cham';
const uint32 kMsgChangePassword = 'cpss';
const uint32 kMsgSetPassword = 'pass';

enum {
	kAutoMountIndex,
	kDeviceIndex,
	kFileIndex,
	kRememberIndex,
	kMountAtIndex,
};

class CheckBoxColumn : public BTitledColumn {
public:
	CheckBoxColumn(const char* name, float width, float min, float max);
	~CheckBoxColumn();

	virtual void DrawField(BField *field, BRect rect, BView *targetView);
	virtual int CompareFields(BField *field1, BField *field2);

	virtual void MouseMoved(BColumnListView *parent, BRow *row, BField *field,
		BRect fieldRect, BPoint point, uint32 buttons, int32 code);
	virtual void MouseDown(BColumnListView *parent, BRow *row, BField *field,
		BRect fieldRect, BPoint point, uint32 buttons);
	virtual	void MouseUp(BColumnListView *parent, BRow *row, BField *field);

	virtual	bool AcceptsField(const BField* field) const;

private:
	BRect _Box(BView* parent, BRect frame);
};

class DriveRow : public BRow {
public:
	DriveRow(const char* device, const char* file, const char* mountAt,
		bool autoMount = false, bool remember = false);
	DriveRow();
	virtual ~DriveRow();

	bool HasDevice() const;
	bool HasMountAt() const;

	const char* File() const;
	void SetFile(const char* file);
	const char* Device() const;
	void SetDevice(const char* device);
	const char* MountAt() const;
	void SetMountAt(const char* mountAt);
	bool AutoMount() const;
	void SetAutoMount(bool autoMount);
	bool Remember() const;
	void SetRemember(bool remember);

private:
	void _Init();
};

class DriveListView : public BColumnListView {
public:
	DriveListView(BRect rect, const char* name, uint32 resizingMode);
	~DriveListView();

	virtual void MessageDropped(BMessage* message, BPoint where);

	DriveRow* FindRowByFile(const char* file);
};


CheckBoxColumn::CheckBoxColumn(const char* name, float width, float min,
		float max)
	: BTitledColumn(name, width, min, max)
{
	SetWantsEvents(true);
}


CheckBoxColumn::~CheckBoxColumn()
{
}


BRect
CheckBoxColumn::_Box(BView* parent, BRect frame)
{
	font_height fontHeight;
	parent->GetFontHeight(&fontHeight);

	BRect rect;
	rect.right = 2.0f + fontHeight.ascent;
	rect.bottom = 2.0f + fontHeight.ascent;
	rect.OffsetBy(frame.left + (frame.Width() - rect.Width()) / 2,
		frame.top + (frame.Height() - rect.Height()) / 2);
	return rect;
}


void
CheckBoxColumn::DrawField(BField *_field, BRect rect, BView *view)
{
	BIntegerField* field = static_cast<BIntegerField*>(_field);

	rgb_color noTint = ui_color(B_PANEL_BACKGROUND_COLOR);
	rgb_color lighten1 = tint_color(noTint, B_LIGHTEN_1_TINT);
	rgb_color lightenMax = tint_color(noTint, B_LIGHTEN_MAX_TINT);
	rgb_color darken1 = tint_color(noTint, B_DARKEN_1_TINT);
	rgb_color darken2 = tint_color(noTint, B_DARKEN_2_TINT);
	rgb_color darken3 = tint_color(noTint, B_DARKEN_3_TINT);
	rgb_color darken4 = tint_color(noTint, B_DARKEN_4_TINT);
	rgb_color darkenmax = tint_color(noTint, B_DARKEN_MAX_TINT);

	rect = _Box(view, rect);

	// Filling
	view->SetHighColor(lightenMax);
	view->FillRect(rect);

	// Box
	if (0/*fOutlined*/) {
		view->SetHighColor(darken3);
		view->StrokeRect(rect);

		rect.InsetBy(1, 1);

		view->BeginLineArray(6);

		view->AddLine(BPoint(rect.left, rect.bottom),
				BPoint(rect.left, rect.top), darken2);
		view->AddLine(BPoint(rect.left, rect.top),
				BPoint(rect.right, rect.top), darken2);
		view->AddLine(BPoint(rect.left, rect.bottom),
				BPoint(rect.right, rect.bottom), darken4);
		view->AddLine(BPoint(rect.right, rect.bottom),
				BPoint(rect.right, rect.top), darken4);

		view->EndLineArray();
	} else {
		view->BeginLineArray(6);

		view->AddLine(BPoint(rect.left, rect.bottom),
				BPoint(rect.left, rect.top), darken1);
		view->AddLine(BPoint(rect.left, rect.top),
				BPoint(rect.right, rect.top), darken1);
		rect.InsetBy(1, 1);
		view->AddLine(BPoint(rect.left, rect.bottom),
				BPoint(rect.left, rect.top), darken4);
		view->AddLine(BPoint(rect.left, rect.top),
				BPoint(rect.right, rect.top), darken4);
		view->AddLine(BPoint(rect.left + 1.0f, rect.bottom),
				BPoint(rect.right, rect.bottom), noTint);
		view->AddLine(BPoint(rect.right, rect.bottom),
				BPoint(rect.right, rect.top + 1.0f), noTint);

		view->EndLineArray();
	}

	// Checkmark
	if (field->Value() != B_CONTROL_OFF) {
		rect.InsetBy(2, 2);

		view->SetHighColor(ui_color(B_KEYBOARD_NAVIGATION_COLOR));
		view->SetPenSize(2);
		view->SetDrawingMode(B_OP_OVER);
			// needed because of anti-aliasing
		view->StrokeLine(BPoint(rect.left, rect.top),
			BPoint(rect.right, rect.bottom));
		view->StrokeLine(BPoint(rect.left, rect.bottom),
			BPoint(rect.right, rect.top));
		view->SetPenSize(1);
		view->SetDrawingMode(B_OP_COPY);
	}
}


int
CheckBoxColumn::CompareFields(BField* _field1, BField* _field2)
{
	BIntegerField* field1 = static_cast<BIntegerField*>(_field1);
	BIntegerField* field2 = static_cast<BIntegerField*>(_field2);

	return field1->Value() - field2->Value();
}


void
CheckBoxColumn::MouseMoved(BColumnListView *parent, BRow *row, BField *field,
	BRect fieldRect, BPoint point, uint32 buttons, int32 code)
{
}


void
CheckBoxColumn::MouseDown(BColumnListView *parent, BRow *row, BField* _field,
	BRect fieldRect, BPoint point, uint32 buttons)
{
	if (row != parent->FocusRow())
		return;

	fieldRect = _Box(parent, fieldRect);
	if (!fieldRect.Contains(point))
		return;

	BIntegerField* field = static_cast<BIntegerField*>(_field);
	field->SetValue(field->Value() == B_CONTROL_ON
		? B_CONTROL_OFF : B_CONTROL_ON);
	parent->Invalidate(fieldRect);
}


void
CheckBoxColumn::MouseUp(BColumnListView *parent, BRow *row, BField *field)
{
}


bool
CheckBoxColumn::AcceptsField(const BField* field) const
{
	return dynamic_cast<const BIntegerField*>(field) != NULL;
}


//	#pragma mark -


DriveRow::DriveRow(const char* device, const char* file, const char* mountAt,
		bool autoMount, bool remember)
	: BRow(20)
{
	_Init();

	SetAutoMount(autoMount);
	SetFile(file);
	SetDevice(device);
	SetMountAt(mountAt);
	SetRemember(remember);
}


DriveRow::DriveRow()
	: BRow(20)
{
	_Init();
}


DriveRow::~DriveRow()
{
}


void
DriveRow::_Init()
{
	SetField(new BIntegerField(B_CONTROL_OFF), kAutoMountIndex);
	SetField(new BStringField(""), kDeviceIndex);
	SetField(new BStringField(""), kFileIndex);
	SetField(new BIntegerField(B_CONTROL_OFF), kRememberIndex);
	SetField(new BStringField(""), kMountAtIndex);
}


bool
DriveRow::HasDevice() const
{
	const char* device = ((BStringField*)GetField(kDeviceIndex))->String();
	return device != NULL && strcmp(device, "-");
}


bool
DriveRow::HasMountAt() const
{
	const char* mountAt = ((BStringField*)GetField(kMountAtIndex))->String();
	return mountAt != NULL && strcmp(mountAt, "-");
}


const char*
DriveRow::File() const
{
	return ((BStringField*)GetField(kFileIndex))->String();
}


void
DriveRow::SetFile(const char* file)
{
	((BStringField*)GetField(kFileIndex))->SetString(file);
}


const char*
DriveRow::Device() const
{
	return ((BStringField*)GetField(kDeviceIndex))->String();
}


void
DriveRow::SetDevice(const char* device)
{
	((BStringField*)GetField(kDeviceIndex))->SetString(device);
}


const char*
DriveRow::MountAt() const
{
	return ((BStringField*)GetField(kMountAtIndex))->String();
}


void
DriveRow::SetMountAt(const char* mountAt)
{
	((BStringField*)GetField(kMountAtIndex))->SetString(mountAt);
}


bool
DriveRow::AutoMount() const
{
	return ((BIntegerField*)GetField(kAutoMountIndex))->Value() != B_CONTROL_OFF;
}


void
DriveRow::SetAutoMount(bool autoMount)
{
	((BIntegerField*)GetField(kAutoMountIndex))->SetValue(autoMount
		? B_CONTROL_ON : B_CONTROL_OFF);
}


bool
DriveRow::Remember() const
{
	return ((BIntegerField*)GetField(kRememberIndex))->Value() != B_CONTROL_OFF;
}


void
DriveRow::SetRemember(bool remember)
{
	((BIntegerField*)GetField(kRememberIndex))->SetValue(remember
		? B_CONTROL_ON : B_CONTROL_OFF);
}


//	#pragma mark -


DriveListView::DriveListView(BRect rect, const char* name, uint32 resizingMode)
	: BColumnListView(rect, name, resizingMode, 0, B_PLAIN_BORDER)
{
	AddColumn(new CheckBoxColumn("Auto", 50, 40, 50), kAutoMountIndex);
	AddColumn(new BStringColumn("Device", 180, 40, 500, B_TRUNCATE_BEGINNING),
		kDeviceIndex);
	AddColumn(new BStringColumn("Encrypted File/Device", 180, 40, 500,
		B_TRUNCATE_MIDDLE), kFileIndex);
	AddColumn(new CheckBoxColumn("Remember", 75, 40, 75), kRememberIndex);
	AddColumn(new BStringColumn("Mount At", 180, 40, 500, B_TRUNCATE_MIDDLE),
		kMountAtIndex);

	SetSortColumn(ColumnAt(1), false, true);
}


DriveListView::~DriveListView()
{
}


void
DriveListView::MessageDropped(BMessage* message, BPoint where)
{
	Window()->PostMessage(message);
}


DriveRow*
DriveListView::FindRowByFile(const char* file)
{
	for (int32 i = 0; i < CountRows(); i++) {
		DriveRow* row = (DriveRow*)RowAt(i);
		if (!strcmp(row->File(), file))
			return row;
	}

	return NULL;
}


//	#pragma mark -


DriveWindow::DriveWindow(const BMessage& settings)
	: BWindow(BRect(100, 100, 500, 500), "DriveEncryption", B_TITLED_WINDOW,
		B_ASYNCHRONOUS_CONTROLS),
	fOldPasswordLength(0),
	fPasswordChanged(false)
{
	bool hasFrame = false;
	BRect frame;
	if (settings.FindRect("window frame", &frame) == B_OK) {
		hasFrame = true;
	} else
		frame = Frame();

	const uint8* oldPassword;
	ssize_t size;
	if (settings.FindData("password", B_RAW_TYPE, (const void**)&oldPassword,
			&size) == B_OK && size > 0) {
		fOldPassword = (uint8*)malloc(size);
		if (fOldPassword != NULL) {
			fOldPasswordLength = size;
			memcpy(fOldPassword, oldPassword, size);
		}
	} else
		fOldPassword = NULL;

	BScreen screen(this);
	if (!hasFrame || !screen.Frame().Contains(frame)) {
		if (frame.Width() > screen.Frame().Width())
			frame.right = frame.left += 300;
		if (frame.Height() > screen.Frame().Height())
			frame.bottom = frame.top += 300;

		// center window on screen
		frame.OffsetTo((screen.Frame().left + screen.Frame().Width()
				- frame.Width()) / 2,
			screen.Frame().top + (screen.Frame().Height() / 4.0)
				- ceil(frame.Height() / 3.0));
	}

	MoveTo(frame.LeftTop());
	ResizeTo(frame.Width(), frame.Height());

	// create menu

	BMenuBar *menuBar = new BMenuBar(BRect(0, 0, Bounds().Width(), 8),
		"menu bar");
	AddChild(menuBar);

	BMenu *menu = new BMenu("File");

	menu->AddItem(new BMenuItem(fOldPassword == NULL
		? "Set Password" B_UTF8_ELLIPSIS : "Change Password" B_UTF8_ELLIPSIS,
		new BMessage(kMsgChangePassword)));

	menu->AddSeparatorItem();

	menu->AddItem(new BMenuItem("Create Encrypted File" B_UTF8_ELLIPSIS,
		new BMessage(kMsgCreateFile), 'N'));
	menu->AddItem(new BMenuItem("Initialize Encrypted File" B_UTF8_ELLIPSIS,
		new BMessage(kMsgNewFile)));
	BMenu *devicesMenu = new BMenu("Initialize Encrypted Device");
	_CollectDevices(devicesMenu, kMsgNewFilePassword);
	menu->AddItem(new BMenuItem(devicesMenu));

	menu->AddSeparatorItem();

	menu->AddItem(new BMenuItem("Add Encrypted File" B_UTF8_ELLIPSIS,
		new BMessage(kMsgAddFile)));

	devicesMenu = new BMenu("Add Encrypted Device");
	_CollectDevices(devicesMenu, B_REFS_RECEIVED);
	menu->AddItem(new BMenuItem(devicesMenu));

	menu->AddSeparatorItem();

	BMenuItem* item = new BMenuItem("About DriveEncryption" B_UTF8_ELLIPSIS,
		new BMessage(B_ABOUT_REQUESTED));
	menu->AddItem(item);
	menu->AddSeparatorItem();

	menu->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q',
		B_COMMAND_KEY));
	menuBar->AddItem(menu);

	item->SetTarget(be_app);

	// create GUI

	BRect rect = Bounds();
	rect.top = menuBar->Frame().bottom + 1;
	BView* top = new BView(rect, "top", B_FOLLOW_ALL, 0);
	top->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
	AddChild(top);

	rect = top->Bounds().InsetByCopy(10, 10);
	BButton* button = new BButton(rect, "remove", "Remove",
		new BMessage(kMsgRemoveFile), B_FOLLOW_LEFT | B_FOLLOW_BOTTOM);
	button->ResizeToPreferred();
	button->MoveTo(rect.left, rect.bottom - button->Bounds().Height());
	top->AddChild(button);

	BButton* mountButton = new BButton(rect, "mount", "Mount",
		new BMessage(kMsgMountFile), B_FOLLOW_LEFT | B_FOLLOW_BOTTOM);
	mountButton->ResizeToPreferred();
	mountButton->MoveTo(button->Frame().right + 10, button->Frame().top);
	top->AddChild(mountButton);

	rect.bottom -= button->Bounds().Height() + 10;
	fListView = new DriveListView(rect, "list", B_FOLLOW_ALL);
	top->AddChild(fListView);

	BMessenger us(this);
	fOpenPanel = new BFilePanel(B_OPEN_PANEL, &us);
	fSavePanel = new BFilePanel(B_SAVE_PANEL, &us);

	// Add all drives we should remember

	BMessage drives;
	if (settings.FindMessage("drives", &drives) == B_OK) {
		const char* file;
		for (int32 i = 0; drives.FindString("file", i, &file) == B_OK; i++) {
			bool autoMount = drives.FindBool("auto mount");
			const char* mountAt = drives.FindString("mount at");

			DriveRow* row = new DriveRow("-", file, mountAt, autoMount, true);
			fListView->AddRow(row);
		}
	}

	// Add all registered drives

	for (int32 i = 0; i < 10; i++) {
		char path[B_PATH_NAME_LENGTH];
		snprintf(path, B_PATH_NAME_LENGTH, "%s/%ld/raw",
			ENCRYPTED_DRIVE_DIRECTORY, i);

		// open the device
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		// set up the info
		encrypted_drive_info info;
		info.magic = ENCRYPTED_DRIVE_MAGIC;
		info.drive_info_size = sizeof(info);

		// issue the ioctl
		status_t error = B_OK;
		if (ioctl(fd, ENCRYPTED_DRIVE_GET_INFO, &info) == 0) {
			DriveRow* row = fListView->FindRowByFile(info.file_name);
			if (row == NULL) {
				row = new DriveRow(info.device_name, info.file_name, "-");
				fListView->AddRow(row);
			} else
				row->SetDevice(info.device_name);

			// find mount point
			int32 cookie = 0;
			dev_t device;
			while (true) {
				device = next_dev(&cookie);
				if (device < 0)
					break;

				fs_info info;
				if (fs_stat_dev(device, &info) == B_OK
					&& !strcmp(path, info.device_name))
					break;
			}

			BPath mountedAt;
			if (device > 0) {
				BVolume volume(device);
				BDirectory root;
				if (volume.GetRootDirectory(&root) == B_OK
					&& mountedAt.SetTo(&root, ".") == B_OK)
					row->SetMountAt(mountedAt.Path());
			}
		}

		close(fd);
	}
}


DriveWindow::~DriveWindow()
{
	delete fOpenPanel;
	delete fSavePanel;

	free(fOldPassword);
}


void
DriveWindow::_Error(const char* format, ...)
{
	va_list args;
	va_start(args, format);

	char string[2048];
	vsnprintf(string, sizeof(string), format, args);

	va_end(args);

	BAlert* alert = new BAlert("", string, "Ok", NULL, NULL, B_WIDTH_AS_USUAL,
		B_STOP_ALERT);
	alert->Go();
}


/*!	Sets the password that is used for logging into the system.
	It will first check if the previous password is valid before it does
	so, though.
*/
status_t
DriveWindow::_SetPassword(BMessage* message)
{
	const char* oldPassword;
	if (message->FindString("old password", &oldPassword) != B_OK
		&& fOldPassword != NULL)
		return B_PERMISSION_DENIED;

	const char* password;
	if (message->FindString("new password", &password) != B_OK)
		return B_BAD_VALUE;

	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0) {
		_Error("Failed to open control device: %s", strerror(errno));
		return errno;
	}

	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);

	if (fOldPassword != NULL) {
		// check if this password decrypts the old one
		uint8 buffer[2048];
		uint32 bufferLength = min_c(fOldPasswordLength
			- ENCRYPTED_DRIVE_SALT_SIZE, sizeof(buffer));
		memcpy(buffer, fOldPassword + ENCRYPTED_DRIVE_SALT_SIZE, bufferLength);

		info.key = (const uint8*)oldPassword;
		info.key_length = strlen(oldPassword);
		info.random_data = fOldPassword;
		info.random_length = fOldPasswordLength;
		info.buffer = buffer;
		info.buffer_length = bufferLength;

		if (ioctl(fd, ENCRYPTED_DRIVE_DECRYPT_BUFFER, &info) != 0) {
			close(fd);
			return errno;
		}

		if (strcmp((const char*)buffer, oldPassword)) {
			close(fd);
			return B_PERMISSION_DENIED;
		}
	}

	free(fOldPassword);
	fOldPassword = NULL;
	fOldPasswordLength = 0;

	// set new one

	uint8 random[2048];
	uint8 buffer[2048];
	uint32 bufferLength = sizeof(buffer);
	uint32 passwordLength = strlen(password);
	passwordLength = min_c(bufferLength, passwordLength);
	memcpy(buffer, password, passwordLength);

	// fill the rest of the buffer with random data
	while (bufferLength > 32 && bufferLength / 2 > passwordLength) {
		bufferLength /= 2;
	}
	if (bufferLength > passwordLength + 1) {
		fill_random_buffer(buffer + passwordLength + 1,
			bufferLength - passwordLength - 1);
	}

	fill_random_buffer(random, sizeof(random));
		// generate random data to be used as salt for the AES encryption

	info.key = (const uint8*)password;
	info.key_length = passwordLength;
	info.random_data = random;
	info.random_length = sizeof(random);
	info.buffer = buffer;
	info.buffer_length = bufferLength;

	if (ioctl(fd, ENCRYPTED_DRIVE_ENCRYPT_BUFFER, &info) != 0) {
 		close(fd);
		return errno;
	}

	fOldPassword = (uint8*)malloc(bufferLength + ENCRYPTED_DRIVE_SALT_SIZE);
	if (fOldPassword != NULL) {
		memcpy(fOldPassword, random, ENCRYPTED_DRIVE_SALT_SIZE);
		memcpy(fOldPassword + ENCRYPTED_DRIVE_SALT_SIZE, buffer, bufferLength);
		fOldPasswordLength = bufferLength + ENCRYPTED_DRIVE_SALT_SIZE;
		fPasswordChanged = true;
	}

	close(fd);
	return fOldPassword != NULL ? B_OK : B_NO_MEMORY;
}


/*!	Iterates over all volumes and checks if this device has any mounted
	volumes. It will also take "raw" devices and their partitions into
	account.
*/
bool
DriveWindow::_IsMounted(BPath& path)
{
	bool isRaw = !strcmp(path.Leaf(), "raw");
	BPath parent;
	uint32 parentLength;
	if (isRaw) {
		path.GetParent(&parent);
		parentLength = strlen(parent.Path());
	}

	int32 cookie = 0;
	dev_t device;
	while (true) {
		device = next_dev(&cookie);
		if (device < 0)
			break;

		fs_info info;
		if (fs_stat_dev(device, &info) != B_OK)
			continue;

		if (!strcmp(path.Path(), info.device_name)
			|| isRaw && !strncmp(parent.Path(), info.device_name, parentLength))
			return true;
	}

	return false;
}


void
DriveWindow::_CollectDevices(BMenu *menu, uint32 what, BEntry *startEntry)
{
	// TODO: we could remove those we already know

	BDirectory directory;
	if (startEntry != NULL)
		directory.SetTo(startEntry);
	else
		directory.SetTo("/dev/disk");

	BEntry entry;
	while (directory.GetNextEntry(&entry) == B_OK) {
		if (entry.IsDirectory()) {
			char name[B_FILE_NAME_LENGTH];
			if (entry.GetName(name) != B_OK || strcmp(name, "encrypted"))
				_CollectDevices(menu, what, &entry);

			continue;
		}

		entry_ref ref;
		if (entry.GetRef(&ref) != B_OK)
			continue;

		BPath path;
		if (entry.GetPath(&path) != B_OK)
			continue;

		off_t size = 0;
		int device = open(path.Path(), O_RDONLY);
		if (device >= 0) {
			device_geometry geometry;
			if (ioctl(device, B_GET_GEOMETRY, &geometry) == 0) {
				size = 1LL * geometry.head_count * geometry.cylinder_count
					* geometry.sectors_per_track * geometry.bytes_per_sector;
			}

			close(device);
		}

		BMessage *message = new BMessage(what);
		message->AddRef("refs", &ref);
		message->AddBool("is device", true);

		BString label = path.Path();
		if (size != 0) {
			char string[64];
			if (size < 1024)
				sprintf(string, "%Ld bytes", size);
			else {
				char *units[] = {(char*)"KB", (char*)"MB", (char*)"GB", (char*)"TB", NULL};
				double value = size;
				int32 i = -1;

				do {
					value /= 1024.0;
					i++;
				} while (value >= 1024 && units[i + 1]);

				sprintf(string, "%.1f %s", value, units[i]);
			}

			label << " (" << string << ")";
		}

		BMenuItem* item = new BMenuItem(label.String(), message);
		if (_IsMounted(path))
			item->SetEnabled(false);

		menu->AddItem(item);
	}
}


void
DriveWindow::_CheckAuthorization(entry_ref& ref, bool mount)
{
	BMessage* message = new BMessage(mount ?
		kMsgCheckAuthorizationAndMount : kMsgCheckAuthorization);
	message->AddRef("ref", &ref);

	BString text = "Enter the password to unlock the encrypted ";
	BPath path(&ref);
	if (!strncmp(path.Path(), "/dev/", 5))
		text << "device";
	else
		text << "image file";
	text << " \"" << path.Path() << "\".";

	PasswordWindow* window = new PasswordWindow("", text.String(), this,
		message);
	window->Show();
}


void
DriveWindow::_RefsReceived(BMessage* refs)
{
	entry_ref ref;
	for (int32 i = 0; refs->FindRef("refs", i, &ref) == B_OK; i++) {
		_CheckAuthorization(ref, false);
	}
}


/*!	Let's you choose a size for the new file image. */
void
DriveWindow::_SaveRequested(BMessage* message)
{
	entry_ref directory;
	const char* name;
	if (message->FindRef("directory", &directory) != B_OK
		|| message->FindString("name", &name) != B_OK)
		return;

	BPath path(&directory);
	path.Append(name);

	BEntry entry(path.Path());
	entry_ref ref;
	entry.GetRef(&ref);

	message = new BMessage(kMsgCreateFileSize);
	message->AddRef("ref", &ref);

	BString text = "Specify the size of the encrypted image file \"";
	text << path.Leaf() << "\".\n";
	BVolume volume(ref.device);

	char string[64];
	off_t free = volume.FreeBytes();
	if (free < 1024)
		snprintf(string, sizeof(string), "%Ld bytes ", free);
	else {
		char *units[] = {(char*)"KB", (char*)"MB", (char*)"GB", (char*)"TB", NULL};
		double size = free;
		int32 i = -1;

		do {
			size /= 1024.0;
			i++;
		} while (size >= 1024 && units[i + 1]);

		snprintf(string, sizeof(string), "%.1f %s", size, units[i]);
	}
	text << "There are " << string << " left on this device.";

	FileSizeWindow* window = new FileSizeWindow("", text.String(),
		2 * 1024 * 1024, free, this, message);
	window->Show();
}


void
DriveWindow::_MountFile(DriveRow* row)
{
	if (row == NULL || !row->HasDevice())
		return;

	const char* mountAt = NULL;
	if (row->HasMountAt())
		mountAt = row->MountAt();

	status_t status = mount_device(row->Device(), mountAt);
	if (status < B_OK)
		_Error("Cannot mount device: %s", strerror(status));
}


/*!	Unregisters a file from the encrypted driver, and removes it from the
	list. If mounted, it will unmount the volume first.
*/
void
DriveWindow::_RemoveFile(DriveRow* row)
{
	if (row == NULL)
		return;

	if (row->HasDevice()) {
		// unregister drive

		// try unmounting first
		// TODO: check if this points to the correct device first!
		if (row->HasMountAt()) {
#ifdef __HAIKU__
			fs_unmount_volume(row->MountAt(), 0);
#else
			unmount(row->MountAt());
#endif
		}

		int fd = open(row->Device(), O_RDONLY);
		if (fd < 0) {
			_Error("Failed to open device \"%s\":\n\t%s",
				row->Device(), strerror(errno));
			return;
		}

		// issue the ioctl
		status_t error = B_OK;
		if (ioctl(fd, ENCRYPTED_DRIVE_UNREGISTER_FILE, NULL) != 0) {
			error = errno;
			_Error("Failed to uninstall device: %s", strerror(error));
		}
		close(fd);

		if (error != B_OK)
			return;
	}

	fListView->RemoveRow(row);
	delete row;
}


/*! Creates a file of the specified size. The file and size are both
	retrieved from the provided \a message.
*/
void
DriveWindow::_CreateFile(BMessage* message)
{
	entry_ref ref;
	off_t size;
	if (message->FindRef("ref", &ref) != B_OK
		|| message->FindInt64("size", &size) != B_OK)
		return;

	BFile file;
	status_t status = file.SetTo(&ref, B_READ_WRITE | B_CREATE_FILE);
	if (status != B_OK) {
		_Error("Could not create file \"%s\":\n\t%s", ref.name,
			strerror(status));
		return;
	}

	status = file.SetSize(size);
	if (status != B_OK) {
		_Error("Could not set file size for \"%s\":\n\t%s", ref.name,
			strerror(status));

		// delete left-overs
		BEntry entry(&ref);
		entry.Remove();
		return;
	}

	message = new BMessage(kMsgNewFilePassword);
	message->AddRef("ref", &ref);
	message->AddBool("confirm", false);
	PostMessage(message);
}


/*!	Searches for a matching DriveRow for the \a info, and returns it
	if it exists. If it does not exist yet, it will create one, and
	add it to the list.
*/
DriveRow*
DriveWindow::_UpdateOrAddRow(encrypted_drive_info& info)
{
	DriveRow* row = fListView->FindRowByFile(info.file_name);
	if (row == NULL) {
		row = new DriveRow(info.device_name, info.file_name, "-");
		fListView->AddRow(row);
	} else {
		row->SetDevice(info.device_name);
		fListView->Invalidate();
	}

	return row;
}


/*!	Initializes a file or device to be used as an encrypted drive.
	Gets a message with entry_ref and password that identify the file
	or device.
*/
void
DriveWindow::_InitializeFile(BMessage* message)
{
	const char* password;
	entry_ref ref;
	if ((message->FindRef("ref", &ref) != B_OK
			&& message->FindRef("refs", &ref) != B_OK)
		|| message->FindString("new password", &password) != B_OK)
		return;

	bool confirm;
	if (message->FindBool("confirm", &confirm) != B_OK)
		confirm = true;

	BPath path(&ref);

	if (confirm) {
		BString text = "This will destroy all data on the ";
		if (message->FindBool("is device"))
			text << "device \"" << path.Path();
		else
			text << "file \"" << path.Leaf();

		text << "\". Are you sure?";
		BAlert* alert = new BAlert("", text.String(), "Yes", "No", NULL,
			B_WIDTH_AS_USUAL, B_WARNING_ALERT);
		if (alert->Go() != 0)
			return;
	}

	// TODO: we might want to fill the device with random data

	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0) {
		_Error("Failed to open control device: %s", strerror(errno));
		return;
	}

	// set up the info
	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);
	info.key = (uint8*)password;
	info.key_length = strlen(password);
	info.read_only = false;

	strcpy(info.file_name, path.Path());

	// generate random data to be used as salt and AES keys
	uint8 random[2048];
	fill_random_buffer(random, sizeof(random));
	info.random_data = random;
	info.random_length = sizeof(random);

	if (ioctl(fd, ENCRYPTED_DRIVE_INITIALIZE_FILE, &info) != 0)
		_Error("Failed to install device: %s", strerror(errno));
	else
		_UpdateOrAddRow(info);

	close(fd);
}


status_t
DriveWindow::_AddFile(BMessage* message, DriveRow** _row)
{
	const char* password;
	entry_ref ref;
	if (message->FindRef("ref", &ref) != B_OK
		|| message->FindString("password", &password) != B_OK)
		return B_BAD_VALUE;

	BPath path(&ref);
	if (path.InitCheck() != B_OK) {
		_Error("Failed to locate file: %s", ref.name);
		return B_ERROR;
	}

	// open the control device
	int fd = open(ENCRYPTED_DRIVE_CONTROL_DEVICE, O_RDONLY);
	if (fd < 0) {
		_Error("Failed to open control device: %s", strerror(errno));
		return errno;
	}

	// set up the info
	encrypted_drive_info info;
	info.magic = ENCRYPTED_DRIVE_MAGIC;
	info.drive_info_size = sizeof(info);
	info.key = (const uint8*)password;
	info.key_length = strlen(password);
	info.random_data = NULL;
	info.random_length = 0;
	info.read_only = false;

	strcpy(info.file_name, path.Path());

	// issue the ioctl
	status_t error = B_OK;
	if (ioctl(fd, ENCRYPTED_DRIVE_REGISTER_FILE, &info) != 0) {
		if (errno != B_PERMISSION_DENIED)
			_Error("Failed to register encrypted drive: %s", strerror(errno));

		close(fd);
		return errno;
	}

	close(fd);

	DriveRow* row = _UpdateOrAddRow(info);
	if (_row != NULL)
		*_row = row;

	return B_OK;
}


void
DriveWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case B_MOUSE_WHEEL_CHANGED:
			if (BView *view = FindView("list"))
				view->MessageReceived(message);
			break;

		case B_REFS_RECEIVED:
			_RefsReceived(message);
			break;

		case B_SIMPLE_DATA:
		{
			BMessage refsReceived(*message);
			refsReceived.what = B_REFS_RECEIVED;
			be_app_messenger.SendMessage(&refsReceived);
			break;
		}

		case kMsgChangePassword:
		{
			ChangePasswordWindow* window = new ChangePasswordWindow("",
				fOldPassword != NULL, this, new BMessage(kMsgSetPassword));
			window->Show();
			break;
		}

		case kMsgSetPassword:
		{
			BMessage reply(B_REPLY);

			status_t status = _SetPassword(message);
			if (status < B_OK)
				reply.AddInt32("error", status);

			message->SendReply(&reply);
			break;
		}

		case kMsgMountFile:
		{
			DriveRow* row = (DriveRow*)fListView->CurrentSelection();
			if (row == NULL)
				break;

			if (row->HasDevice())
				_MountFile(row);
			else {
				BEntry entry(row->File());
				entry_ref ref;
				if (entry.GetRef(&ref) == B_OK)
					_CheckAuthorization(ref, true);
			}
			break;
		}

		case kMsgRemoveFile:
			_RemoveFile((DriveRow*)fListView->CurrentSelection());
			break;

		case kMsgAddFile:
		{
			BMessage refs(B_REFS_RECEIVED);
			fOpenPanel->SetMessage(&refs);
			fOpenPanel->Show();
			break;
		}

		case kMsgCreateFile:
			fSavePanel->SetButtonLabel(B_DEFAULT_BUTTON, "Create");
			fSavePanel->Window()->SetTitle("DriveEncryption: Create Encrypted File");
			fSavePanel->Show();
			break;
		case B_SAVE_REQUESTED:
			_SaveRequested(message);
			break;
		case kMsgCreateFileSize:
			_CreateFile(message);
			break;

		case kMsgNewFile:
		{
			BMessage newFile(kMsgNewFilePassword);
			fOpenPanel->SetMessage(&newFile);
			fOpenPanel->Show();
			break;
		}
		case kMsgNewFilePassword:
		{
			BMessage* initialize = new BMessage(*message);
			initialize->what = kMsgInitializeFile;

			ChangePasswordWindow* window = new ChangePasswordWindow("",
				false, this, initialize);
			window->Show();
			break;
		}
		case kMsgInitializeFile:
			_InitializeFile(message);
			break;

		case kMsgCheckAuthorization:
		case kMsgCheckAuthorizationAndMount:
		{
			const char* password;
			if (message->FindString("password", &password) != B_OK)
				break;

			BMessage reply(B_REPLY);
			DriveRow* row;

			status_t status = _AddFile(message, &row);
			if (status < B_OK)
				reply.AddInt32("error", status);

			message->SendReply(&reply);

			if (status == B_OK
				&& message->what == kMsgCheckAuthorizationAndMount)
				_MountFile(row);
			break;
		}

		default:
			BWindow::MessageReceived(message);
	}
}


bool
DriveWindow::QuitRequested()
{
	BMessage update(kMsgSettingsChanged);
	update.AddRect("window frame", Frame());

	// add drives that should be remembered
	BMessage drives;
	for (int32 i = 0; i < fListView->CountRows(); i++) {
		DriveRow* row = (DriveRow*)fListView->RowAt(i);
		if (row->Remember() || row->AutoMount()) {
			drives.AddString("file", row->File());
			drives.AddBool("auto mount", row->AutoMount());
			drives.AddString("mount at", row->MountAt());
		}
	}
	update.AddMessage("drives", &drives);

	if (fPasswordChanged) {
		update.AddData("password", B_RAW_TYPE, fOldPassword,
			fOldPasswordLength);
	}

	be_app_messenger.SendMessage(&update);

	be_app_messenger.SendMessage(B_QUIT_REQUESTED);
	return true;
}

