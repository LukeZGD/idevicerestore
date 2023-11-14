AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src docs

SUBDIRS+=include
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libidevicerestore.pc

EXTRA_DIST = \
	docs \
	README.md \
	git-version-gen

dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
