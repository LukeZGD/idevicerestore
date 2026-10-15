#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>

//#define LOG(fmt, ...) \
//do { \
//fprintf(stderr, "[TEST] " fmt "\n", ##__VA_ARGS__); \
//} while (0)

#define LOG(fmt, ...) do { } while (0)

struct CodeDirectory {
	uint32_t magic;
	uint32_t length;
	uint32_t version;
	uint32_t flags;
	uint32_t hashOffset;
	uint32_t identOffset;
	uint32_t nSpecialSlots;
	uint32_t nCodeSlots;
	uint32_t codeLimit;
	uint8_t hashSize;
	uint8_t hashType;
	uint8_t platform;
	uint8_t pageSize;
	/* ... */
};

struct CodeHash {
	unsigned char hash[CC_SHA1_DIGEST_LENGTH];
};

static uint32_t read_u32_be(const void *p)
{
	const unsigned char *b = (const unsigned char *)p;
	return (uint32_t)b[3] | ((uint32_t)b[2] << 8) | ((uint32_t)b[1] << 16) | ((uint32_t)b[0] << 24);
}

static void write_u32_le(void *p, uint32_t v)
{
	unsigned char *b = (unsigned char *)p;
	b[0] = (unsigned char)(v & 0xFFu);
	b[1] = (unsigned char)((v >> 8) & 0xFFu);
	b[2] = (unsigned char)((v >> 16) & 0xFFu);
	b[3] = (unsigned char)((v >> 24) & 0xFFu);
}

// PF32
// WARN: LE only
// TODO: support big endian

static uint32_t bit_range(uint32_t x, int start, int end)
{
	x = (x << (31 - start)) >> (31 - start);
	x = (x >> end);
	return x;
}

static uint32_t ror(uint32_t x, int places)
{
	return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
	if (bit_range(imm12, 11, 10) == 0) {
		switch (bit_range(imm12, 9, 8)) {
			case 0:
				return bit_range(imm12, 7, 0);
			case 1:
				return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
			case 2:
				return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
			case 3:
				return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
			default:
				return 0;
		}
	}
	uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
	return ror(unrotated_value, bit_range(imm12, 11, 7));
}

static int insn_is_32bit(uint16_t* i)
{
	return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_ldr_literal(uint16_t* i)
{
	return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i)
{
	if ((*i & 0xF800) == 0x4800) {
		return (*i >> 8) & 7;
	}
	else if ((*i & 0xFF7F) == 0xF85F) {
		return (*(i + 1) >> 12) & 0xF;
	}
	return -1;
}

static int insn_ldr_literal_imm(uint16_t* i)
{
	if ((*i & 0xF800) == 0x4800) {
		return (*i & 0xFF) << 2;
	}
	else if ((*i & 0xFF7F) == 0xF85F) {
		return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
	}
	return 0;
}

static int insn_is_add_reg(uint16_t* i)
{
	if ((*i & 0xFE00) == 0x1800) {
		return 1;
	}
	else if ((*i & 0xFF00) == 0x4400) {
		return 1;
	}
	else if ((*i & 0xFFE0) == 0xEB00) {
		return 1;
	}
	return 0;
}

static int insn_add_reg_rd(uint16_t* i)
{
	if ((*i & 0xFE00) == 0x1800) {
		return (*i & 7);
	}
	else if ((*i & 0xFF00) == 0x4400) {
		return (*i & 7) | ((*i & 0x80) >> 4);
	}
	else if ((*i & 0xFFE0) == 0xEB00) {
		return (*(i + 1) >> 8) & 0xF;
	}
	return 0;
}

static int insn_add_reg_rn(uint16_t* i)
{
	if ((*i & 0xFE00) == 0x1800) {
		return ((*i >> 3) & 7);
	}
	else if ((*i & 0xFF00) == 0x4400) {
		return (*i & 7) | ((*i & 0x80) >> 4);
	}
	else if ((*i & 0xFFE0) == 0xEB00) {
		return (*i & 0xF);
	}
	return 0;
}

static int insn_add_reg_rm(uint16_t* i)
{
	if ((*i & 0xFE00) == 0x1800) {
		return (*i >> 6) & 7;
	}
	else if ((*i & 0xFF00) == 0x4400) {
		return (*i >> 3) & 0xF;
	}
	else if ((*i & 0xFFE0) == 0xEB00) {
		return *(i + 1) & 0xF;
	}
	return 0;
}

static int insn_is_movt(uint16_t* i)
{
	return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i)
{
	return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i)
{
	return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i)
{
	if ((*i & 0xF800) == 0x2000) {
		return 1;
	}
	else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return 1;
	}
	else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return 1;
	}
	return 0;
}

static int insn_mov_imm_rd(uint16_t* i)
{
	if ((*i & 0xF800) == 0x2000) {
		return (*i >> 8) & 7;
	}
	else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return (*(i + 1) >> 8) & 0xF;
	}
	else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return (*(i + 1) >> 8) & 0xF;
	}
	return 0;
}

static int insn_mov_imm_imm(uint16_t* i)
{
	if ((*i & 0xF800) == 0x2000) {
		return *i & 0xF;
	}
	else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
	}
	else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
	}
	return 0;
}

static unsigned int make_b_w(int pos, int tgt)
{
	int delta = tgt - pos - 4;
	int abs_delta = (delta < 0) ? -delta : delta;
	const int range = 0x400000;
	const unsigned short omask[4] = { 0xB800, 0xB000, 0x9800, 0x9000 };
	unsigned short upper, lower;
	int n;
	
	if (abs_delta >= range * 4) {
		return 0;
	}
	
	n = abs_delta / range;
	delta -= n * range;
	
	upper = 0xF000 | ((delta >> 12) & 0x7FF);
	lower = omask[n] | ((delta >> 1) & 0x7FF);
	
	return (unsigned int)upper | ((unsigned int)lower << 16);
}

// Find PC-relative references to a certain address (relative to data). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* data, size_t size, uint16_t* insn, uint32_t address)
{
	uint16_t* current_instruction = insn;
	uint32_t value[16];
	memset(value, 0, sizeof(value));
	
	while ((uintptr_t)current_instruction < (uintptr_t)(data + size)) {
		if (insn_is_mov_imm(current_instruction)) {
			value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
		}
		else if (insn_is_ldr_literal(current_instruction)) {
			uintptr_t literal_address  = (uintptr_t)data + ((((uintptr_t)current_instruction - (uintptr_t)data) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
			if (literal_address >= (uintptr_t)data && (literal_address + 4) <= ((uintptr_t)data + size)) {
				value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
			}
		}
		else if(insn_is_movt(current_instruction)) {
			int reg = insn_movt_rd(current_instruction);
			value[reg] |= insn_movt_imm(current_instruction) << 16;
			if (value[reg] == address) {
				return current_instruction;
			}
		}
		else if (insn_is_add_reg(current_instruction)) {
			int reg = insn_add_reg_rd(current_instruction);
			if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
				value[reg] += ((uintptr_t)current_instruction - (uintptr_t)data) + 4;
				if (value[reg] == address) {
					return current_instruction;
				}
			}
		}
		current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
	}
	
	return NULL;
}

static uint32_t find_xref_begin(uint32_t region, uint8_t* data, size_t size, const char* str)
{
	uint8_t* magicStr = memmem(data, size, str, strlen(str));
	if (!magicStr) {
		return 0;
	}
	uint16_t* ref = find_literal_ref(region, data, size, (uint16_t*) data, (uintptr_t)magicStr - (uintptr_t)data);
	if (!ref) {
		return 0;
	}
	uint16_t* pref = ref;
	pref -= 2;
	if (!insn_is_32bit(pref)) {
		pref += 1;
	}
	if (insn_is_ldr_literal(pref)) {
		return (uintptr_t)pref - (uintptr_t)data;
	}
	
	uint16_t* insn = NULL;
	uint16_t* current_insn = ref;
	while ((uintptr_t)current_insn < (uintptr_t)(data + size)) {
		if (insn_is_mov_imm(current_insn)) {
			insn = current_insn;
			break;
		}
		
		pref = current_insn;
		pref -= 2;
		if (!insn_is_32bit(pref)) {
			pref += 1;
		}
		current_insn = pref;
	}
	if (!insn) {
		return 0;
	}
	return (uintptr_t)insn - (uintptr_t)data;
}

static uint32_t find_image_passed_signature(uint32_t region, uint8_t* data, size_t size)
{
	return find_xref_begin(region, data, size, "Image passed signature verification");
}

static uint32_t find_image_failed_signature(uint32_t region, uint8_t* data, size_t size)
{
	return find_xref_begin(region, data, size, "Image failed signature verification");
}

static uint32_t buggy_find_csdir_magic(uint32_t region, uint8_t* data, size_t size)
{
	// 0xfade0c02
	const uint8_t search_magic[] = {0xfa, 0xde, 0x0c, 0x02};
	uint8_t* magic = memmem(data, size, search_magic, sizeof(search_magic));
	if (!magic) {
		return 0;
	}
	return (uintptr_t)magic - (uintptr_t)data;
}

static int validateHash(unsigned char *pageHash, unsigned char *hash)
{
	bool equal = true;
	int i = 0;
	
	char pageHashStr[128];
	memset(pageHashStr, 0, 128);
	char hashStr[128];
	memset(hashStr, 0, 128);
	
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
		sprintf(pageHashStr, "%s%02x", pageHashStr, pageHash[i]);
	}
	
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
		sprintf(hashStr, "%s%02x", hashStr, hash[i]);
	}
	
	for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
		if (pageHash[i] != hash[i]) {
			equal = false;
			hash[i] = pageHash[i];
		}
	}
	
	if (equal != true) {
		LOG("%s %s %s", pageHashStr, equal == true ? "==" : "!=", hashStr);
	}
	return 0;
}

int patch_asr(uint8_t* data, size_t length)
{
	uint32_t text_vmaddr = 0;
	const struct mach_header *hdr = (struct mach_header *)data;
	if (hdr->magic != MH_MAGIC) {
		return -1;
	}
	const unsigned char *q = (unsigned char*)hdr + sizeof(struct mach_header);
	
	for (int i = 0; i < hdr->ncmds; i++) {
		const struct load_command *cmd = (struct load_command *)q;
		if (cmd->cmd == LC_SEGMENT) {
			const struct segment_command *seg = (struct segment_command *)q;
			if (!strcmp(seg->segname, "__TEXT")) {
				text_vmaddr = seg->vmaddr;
			}
		}
		q = q + cmd->cmdsize;
	}
	
	uint32_t image_passed_signature = find_image_passed_signature(text_vmaddr, data, length);
	if (!image_passed_signature) {
		return -1;
	}
	uint32_t image_failed_signature = find_image_failed_signature(text_vmaddr, data, length);
	if (!image_failed_signature) {
		return -1;
	}
	
	uint32_t opcode = make_b_w(image_failed_signature, image_passed_signature);
	write_u32_le(data + image_failed_signature, opcode);
	
	uint32_t csdir_start = buggy_find_csdir_magic(text_vmaddr, data, length);
	if (!csdir_start) {
		return -1;
	}
	const struct CodeDirectory *codeDirectory = (struct CodeDirectory *)(data + csdir_start);
	
	size_t codeLimit = read_u32_be(&codeDirectory->codeLimit);
	size_t hashOffset = read_u32_be(&codeDirectory->hashOffset);
	struct CodeHash *codeHash = (struct CodeHash *)(data + csdir_start + hashOffset); // nCodeSlot start
	
	unsigned char pageHash[CC_SHA1_DIGEST_LENGTH];
	
	size_t pageSize = 1 << codeDirectory->pageSize;
	
	// check: nCodeSlots only
	LOG("checking cs slots...");
	for (int p = 0; p < codeLimit; p += pageSize) {
		CC_SHA1_CTX ctx;
		CC_SHA1_Init(&ctx);
		
		if(p + pageSize < codeLimit) {
			CC_SHA1_Update(&ctx, data + p, (CC_LONG)pageSize);
		}
		else {
			CC_SHA1_Update(&ctx, data + p, (CC_LONG)(codeLimit - p));
		}
		CC_SHA1_Final(pageHash, &ctx);
		
		// check and fix cs slot...
		validateHash(pageHash, codeHash->hash);
		
		// push 1-slot
		codeHash += 1;
	}
	
	return 0;
}
