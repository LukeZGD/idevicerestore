libDER_CFLAGS="-DDER_TAG_SIZE=8"

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(LFS_CFLAGS) \
	$(libirecovery_CFLAGS) \
	$(libimobiledevice_CFLAGS) \
	$(libusbmuxd_CFLAGS) \
	$(libplist_CFLAGS) \
	$(limd_glue_CFLAGS) \
	$(libtatsu_CFLAGS) \
	$(libzip_CFLAGS) \
	$(zlib_CFLAGS) \
	$(libcurl_CFLAGS)

AM_LDFLAGS = \
	$(AC_LDFLAGS) \
	$(libirecovery_LIBS) \
	$(libimobiledevice_LIBS) \
	$(libusbmuxd_LIBS) \
	$(libplist_LIBS) \
	$(limd_glue_LIBS) \
	$(libtatsu_LIBS) \
	$(libzip_LIBS) \
	$(zlib_LIBS) \
	$(libcurl_LIBS)

AM_LDADD = $(AC_LDADD)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = \
	idevicerestore.c idevicerestore.h \
	endianness.h \
	common.c common.h \
	fls.c fls.h \
	mbn.c mbn.h \
	img3.c img3.h \
	img4.c img4.h \
	ftab.c ftab.h \
	ipsw.c ipsw.h \
	normal.c normal.h \
	dfu.c dfu.h \
	recovery.c recovery.h \
	restore.c restore.h \
	asr.c asr.h \
	fdr.c fdr.h \
	ace3.c ace3.h \
	download.c download.h \
	locking.c locking.h
if HAVE_LIMERA1N
idevicerestore_SOURCES += limera1n_payload.h limera1n.c limera1n.h
endif
idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)
idevicerestore_LDADD = $(AM_LDADD)
if HAVE_TURDUS_MERULA
idevicerestore_SOURCES += \
	lz4.c lz4.h \
	lz4hc.c lz4hc.h \
	libDER/DER_Decode.c libDER/DER_Decode.h \
	libDER/DER_Encode.c libDER/DER_Encode.h \
	libDER/oids.c libDER/oids.h \
	libDER/asn1Types.h libDER/libDER_config.h libDER/libDER.h \
	pongo.c pongo.h \
	stuff/cpf_bin.c stuff/cpf_bin.h \
	stuff/kpf_bin.c stuff/kpf_bin.h \
	stuff/overlay_bin.c stuff/overlay_bin.h \
	stuff/Pongo_bin.c stuff/Pongo_bin.h \
	stuff/sep_racer_bin.c stuff/sep_racer_bin.h \
	stuff/union_bin.c stuff/union_bin.h
idevicerestore_CFLAGS += -DHAVE_TURDUS_MERULA $(libDER_CFLAGS) $(libfragmentzip_CFLAGS)
idevicerestore_LDFLAGS += $(libfragmentzip_LIBS)
endif
if HAVE_LIBHFSPLUS
idevicerestore_SOURCES += \
	libhfsplus/asr_patch.c libhfsplus/asr_patch.h libhfsplus/hfs_patch_asr.h \
	libhfsplus/common/abstractfile.c libhfsplus/common/abstractfile.h libhfsplus/common/libhfsplus-common.h \
	libhfsplus/hfs/btree.c libhfsplus/hfs/catalog.c libhfsplus/hfs/extents.c libhfsplus/hfs/fastunicodecompare.c \
	libhfsplus/hfs/flatfile.c libhfsplus/hfs/hfs.c libhfsplus/hfs/hfscompress.c libhfsplus/hfs/hfscompress.h libhfsplus/hfs/hfslib.c \
	libhfsplus/hfs/hfslib.h libhfsplus/hfs/hfsplus.h libhfsplus/hfs/rawfile.c libhfsplus/hfs/utility.c libhfsplus/hfs/volume.c libhfsplus/hfs/xattr.c
endif
