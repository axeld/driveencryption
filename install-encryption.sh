#!/bin/sh

# install driver and make symlink
copyattr -d driver/encrypted_drive /boot/home/config/non-packaged/add-ons/kernel/drivers/bin/
mkdir -p /boot/home/config/non-packaged/add-ons/kernel/drivers/dev/disk/
ln -fs ../../bin/encrypted_drive /boot/home/config/non-packaged/add-ons/kernel/drivers/dev/disk/

# install command line tool
copyattr -d bin/encrypted_drive_control /boot/home/config/non-packaged/bin

alert "The encryption driver and command line tool have been installed successfully.

You can put \"DriveEncryption\" and \"Login\" where you prefer to use them."
