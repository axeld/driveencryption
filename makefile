all: default
default install:
	@cd lib; make -f makefile $@
	@cd driver; make -f makefile $@
	@cd bin; make -f makefile $@
	@cd gui; make -f makefile $@
	@cd login; make -f makefile $@
	@cd test; make -f makefile $@

lib:
	@cd lib; make -f makefile
driver:
	@cd driver; make -f makefile
bin:
	@cd bin; make -f makefile
gui:
	@cd gui; make -f makefile
login:
	@cd login; make -f makefile
test:
	@cd test; make -f makefile

.PHONY : lib driver bin gui login test

# Sets some attributes on the "Read Me" and install-encryption.sh files
# from SVN properties.
# You will need to have Haiku's "addattr" installed for this to work.
attrs:
	svn propget beos:styles --strict Read\ Me >/tmp/attr.styles
	addattr -f /tmp/attr.styles -t raw styles Read\ Me
	svn propget beos:BEOS:TYPE --strict Read\ Me >/tmp/attr.type
	addattr -f /tmp/attr.type -t "'MIMS'" BEOS:TYPE Read\ Me
	svn propget beos:BEOS:TYPE --strict install-encryption.sh >/tmp/attr.type
	addattr -f /tmp/attr.type -t "'MIMS'" BEOS:TYPE install-encryption.sh
	svn propget beos:BEOS:TYPE --strict makefile >/tmp/attr.type
	addattr -f /tmp/attr.type -t "'MIMS'" BEOS:TYPE makefile

# Updates the SVN property to contain an up-to-date "styles" attribute.
# You will need to have Haiku's "catattr" installed for this to work.
update-svn-attrs:
	catattr --raw styles Read\ Me >/tmp/attr.styles
	svn propset beos:styles -F /tmp/attr.styles Read\ Me
	catattr --raw BEOS:TYPE Read\ Me >/tmp/attr.type
	svn propset beos:BEOS:TYPE -F /tmp/attr.type Read\ Me
	catattr --raw BEOS:TYPE install-encryption.sh >/tmp/attr.type
	svn propset beos:BEOS:TYPE -F /tmp/attr.type install-encryption.sh
	catattr --raw BEOS:TYPE makefile >/tmp/attr.type
	svn propset beos:BEOS:TYPE -F /tmp/attr.type makefile

hpkg default:
	mkdir -p pkg/add-ons/kernel/drivers/bin
	mkdir -p pkg/add-ons/kernel/drivers/dev/disk
	mkdir -p pkg/bin
	mkdir -p pkg/apps
	mkdir -p pkg/data/licenses
	cp .PackageInfo pkg/
	cp driver/encrypted_drive pkg/add-ons/kernel/drivers/bin
	ln -fs ../../bin/encrypted_drive pkg/add-ons/kernel/drivers/dev/disk/
	cp bin/encrypted_drive_control pkg/bin/
	cp login/Login pkg/apps/
	cp gui/DriveEncryption pkg/apps/
	cp lib/TrueCrypt\ License.txt pkg/data/licenses/TrueCrypt
	package create -C pkg drive_encryption-r1.1~alpha1-1-x86_gcc2.hpkg

src-distr:
	mkdir -p distr/src/driver
	mkdir -p distr/src/bin
	mkdir -p distr/src/gui
	mkdir -p distr/src/login
	mkdir -p distr/src/headers
	cp driver/*.[ch]* driver/makefile driver/TrueCrypt\ License.txt distr/src/driver/
	cp bin/*.[ch]* bin/makefile distr/src/bin/
	cp gui/*.[ch]* gui/makefile distr/src/gui/
	cp login/*.[ch]* login/makefile distr/src/login/
	cp headers/*.h distr/src/headers/
	cp TODO distr/src/
	copyattr -d Read\ Me distr/src/
	copyattr -d install-encryption.sh distr/src/
	copyattr -d makefile distr/src/

