all: default
default clean install:
	@cd lib; make -f Makefile $@
	@cd driver; make -f Makefile $@
	@cd bin; make -f Makefile $@
	@cd gui; make -f Makefile $@
	@cd login; make -f Makefile $@

lib:
	@cd lib; make -f Makefile
driver:
	@cd driver; make -f Makefile
bin:
	@cd bin; make -f Makefile
gui:
	@cd gui; make -f Makefile
login:
	@cd login; make -f Makefile
test:
	@cd test; make -f Makefile

.PHONY : lib driver bin gui login test

VERSION = 1.1.0-1

hpkg: default
	mkdir -p pkg/add-ons/kernel/drivers/bin
	mkdir -p pkg/add-ons/kernel/drivers/dev/disk
	mkdir -p pkg/bin
	mkdir -p pkg/apps
	mkdir -p pkg/data/licenses
	cp .PackageInfo pkg/
	cp driver/$(OBJ_DIR)/encrypted_drive pkg/add-ons/kernel/drivers/bin
	ln -fs ../../bin/encrypted_drive pkg/add-ons/kernel/drivers/dev/disk/
	cp bin/$(OBJ_DIR)/encrypted_drive_control pkg/bin/
	cp login/$(OBJ_DIR)/Login pkg/apps/
	cp gui/$(OBJ_DIR)/DriveEncryption pkg/apps/
	cp lib/TrueCrypt\ License.txt pkg/data/licenses/TrueCrypt
	package create -C pkg drive_encryption-$(VERSION)-$(shell getarch).hpkg
