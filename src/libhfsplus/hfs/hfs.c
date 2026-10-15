#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "hfsplus.h"
#include <dirent.h>

#include "hfslib.h"
#include "../common/abstractfile.h"
#include "../asr_patch.h"
#include <inttypes.h>

char endianness;

extern int patch_asr(uint8_t* data, size_t length);

static void TestByteOrder()
{
	short int word = 0x0001;
	char *byte = (char *) &word;
	endianness = byte[0] ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}

static int doPatchASR(Volume* volume, const char* filePath)
{
	void* inBuffer;
	size_t inBufferSize;
	AbstractFile* inBufferFile;
	AbstractFile* outBufferFile;
	
	inBuffer = malloc(1);
	inBufferSize = 0;
	inBufferFile = createAbstractFileFromMemoryFile((void**)&inBuffer, &inBufferSize);
	
	get_hfs(volume, filePath, inBufferFile);
	inBufferFile->close(inBufferFile);
	
	patch_asr(inBuffer, inBufferSize);
	
	inBufferFile = createAbstractFileFromMemoryFile((void**)&inBuffer, &inBufferSize);
	add_hfs(volume, inBufferFile, filePath);
	
	return 0;
}

int patchASR(void* buf, size_t len)
{
	TestByteOrder();
	
	io_func* io;
	Volume* volume;
	io = IOFuncFromAbstractFile(createAbstractFileFromMemoryFile((void**)&buf, &len));
	if (io == NULL) {
		fprintf(stderr, "error: Cannot open image-file.\n");
		return 1;
	}
	
	volume = openVolume(io);
	if (volume == NULL) {
		fprintf(stderr, "error: Cannot open volume.\n");
		CLOSE(io);
		return 1;
	}
	
	doPatchASR(volume, "usr/sbin/asr");
	
	closeVolume(volume);
	CLOSE(io);
	return 0;
}
