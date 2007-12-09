#!/bin/sh

# install driver and make symlink
copyattr -d encrypted_drive /boot/home/config/add-ons/kernel/drivers/bin/
ln -fs ../../bin/encrypted_drive /boot/home/config/add-ons/kernel/drivers/dev/disk/

# install command line tool
copyattr -d encrypted_drive_control /boot/home/config/bin/

alert "The encryption driver and command line tool have been installed successfully.

You can put \"DriveEncryption\" and \"Login\" where you prefer to use them."
