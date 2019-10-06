# DriveEncryption
version 1.0.0 alpha 1 (23.11.2007)
--

## introduction.
DriveEncryption is a suite of programs to allow you to encrypt devices and file images. The encryption is done via the AES algorithm, and protected via a password.
It can also use devices created with TrueCrypt (http://www.truecrypt.org/), available for Windows and Linux, as long as you've created them to use the AES encryption algorithm and a RIPEMD-160 hash algorithm protected password.

Note, this is an alpha release, so this software might not work for you as expected.
Please report any bugs to axeld@pinc-software.de.

## disclaimer & license.
This product is copyrighted ©2007 by pinc Software. All Rights Reserved.
You may freely use this product as is. However, no warranty is given on the functionality. In no event  shall the author be liable for any damages and data loss it caused.
Portions of this product are based in part on TrueCrypt, freely available at http://www.truecrypt.org/. All other files may be distributed under the terms of the MIT license.

## installation.
The kernel driver has to be placed in /boot/home/config/add-ons/kernel/drivers/bin. Also, you need to create a symlink from .../drivers/dev/disk/ to the bin directory. The provided installation script will take care about this for you. It will also install a command line tool "encrypted_drive_control" in /boot/home/config/bin/.
The applications can be put anywhere you want.

## usage.
There are no docs for DriveEncryption yet. You will have to create an encrypted file image or disk device, choose a password for it, and you're done. Using the password and encrypted_drive_control, DriveEncryption, or Login, you can then access the data on the encrypted device, like you can with any other mounted volume. You can also freely choose the file system which with the disk image will be formatted. Just keep in mind that if you plan to use the image on Windows or Linux, you should choose a file system these systems can work with.
The password you set in DriveEncryption is the password you have to enter when using the Login application. When you enable the "Auto" mode for a device, you can automatically unlock and mount that device using the Login application - you will just have to make sure the same password is used for the device as well as Login.
Upon having entered the correct password, Login will start a script called LoginScript in /boot/home/config/boot/. You may want to alter /system/boot/Bootscript to call Login, and the LoginScript to launch Tracker and Deskbar.

## history.
version 1.0.0 alpha 1 (23.11.2007)
	- initial release.

## author.
"DriveEncryption" is written by Axel Dörfler <axeld@pinc-software.de>.
Portions of the kernel driver are based in part on TrueCrypt, freely available at http://www.truecrypt.org/.
visit: http://www.pinc-software.com/

Have fun.
