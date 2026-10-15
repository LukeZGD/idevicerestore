#include "pongo.h"
#include "lz4.h"
#include "lz4hc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libimobiledevice-glue/sha.h>

#include "dfu.h"
#include "idevicerestore.h"
#include "common.h"

#include "stuff/Pongo_bin.h"
#include "stuff/cpf_bin.h"
#include "stuff/kpf_bin.h"
#include "stuff/sep_racer_bin.h"
#include "stuff/overlay_bin.h"
#include "stuff/union_bin.h"

static enum AUTOBOOT_STAGE CURRENT_STAGE = NONE;

static const uint8_t lz4dec_bin[] = {
	0xf2, 0x03, 0x1e, 0xaa, 0xf1, 0x03, 0x00, 0xaa, 0xe1, 0x07, 0x61, 0xb2,
	0xe3, 0x27, 0x17, 0x32, 0x25, 0x00, 0x03, 0x8b, 0x42, 0x0f, 0x00, 0x18,
	0x02, 0x00, 0x00, 0x34, 0xa0, 0x00, 0x02, 0xcb, 0x00, 0xec, 0x7c, 0x92,
	0xe4, 0x0e, 0x00, 0x10, 0x66, 0x01, 0x00, 0x10, 0x07, 0x34, 0x80, 0xd2,
	0xc8, 0x44, 0x40, 0xb8, 0xa8, 0x44, 0x00, 0xb8, 0xe7, 0x10, 0x00, 0x51,
	0xa7, 0xff, 0xff, 0x35, 0x25, 0x00, 0x03, 0x8b, 0xa6, 0x80, 0x06, 0x91,
	0x22, 0x00, 0x00, 0x94, 0x25, 0x00, 0x03, 0x8b, 0xa0, 0x00, 0x1f, 0xd6,
	0x1f, 0x00, 0x04, 0xeb, 0xe0, 0x01, 0x00, 0x54, 0xe8, 0x00, 0x00, 0x54,
	0xe6, 0x03, 0x00, 0xaa, 0x87, 0x20, 0xc1, 0xa8, 0xc7, 0x20, 0x81, 0xa8,
	0xdf, 0x00, 0x05, 0xeb, 0xa3, 0xff, 0xff, 0x54, 0x08, 0x00, 0x00, 0x14,
	0x84, 0x00, 0x02, 0x8b, 0x84, 0x3c, 0x00, 0x91, 0x84, 0xec, 0x7c, 0x92,
	0x87, 0x20, 0xff, 0xa9, 0xa7, 0x20, 0xbf, 0xa9, 0xbf, 0x00, 0x00, 0xeb,
	0xa8, 0xff, 0xff, 0x54, 0x19, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0xb4,
	0xe5, 0x07, 0x61, 0xb2, 0xa6, 0x00, 0x00, 0x8b, 0x0b, 0x00, 0x00, 0x94,
	0x48, 0x42, 0x38, 0xd5, 0x1f, 0x31, 0x00, 0xf1, 0x41, 0x00, 0x00, 0x54,
	0x1f, 0x10, 0x1e, 0xd5, 0x1f, 0x10, 0x18, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
	0xe0, 0x03, 0x11, 0xaa, 0xfe, 0x03, 0x12, 0xaa, 0xf2, 0x07, 0x61, 0xb2,
	0x40, 0x02, 0x1f, 0xd6, 0x9f, 0x3f, 0x03, 0xd5, 0x25, 0x7e, 0x0b, 0xd5,
	0xa5, 0x00, 0x01, 0x91, 0xbf, 0x00, 0x06, 0xeb, 0xa3, 0xff, 0xff, 0x54,
	0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5, 0x1f, 0x75, 0x08, 0xd5,
	0xdf, 0x3f, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6, 0xef, 0x03, 0x1e, 0xaa,
	0xee, 0x03, 0x01, 0xaa, 0x02, 0x00, 0x02, 0xab, 0x22, 0x07, 0x00, 0x54,
	0x23, 0x00, 0x03, 0xab, 0xe2, 0x06, 0x00, 0x54, 0x1f, 0x00, 0x02, 0xeb,
	0xa2, 0x06, 0x00, 0x54, 0x04, 0x14, 0x40, 0x38, 0x85, 0x0c, 0x00, 0x12,
	0x84, 0x1c, 0x04, 0x53, 0xe4, 0x01, 0x00, 0x34, 0x26, 0x00, 0x00, 0x94,
	0x3f, 0x00, 0x00, 0xeb, 0x22, 0x20, 0x42, 0xfa, 0x02, 0x20, 0x42, 0xfa,
	0x22, 0x30, 0x43, 0xfa, 0x46, 0x00, 0x00, 0xcb, 0x82, 0x30, 0x46, 0xfa,
	0x66, 0x00, 0x01, 0xcb, 0x82, 0x90, 0x46, 0xfa, 0xe8, 0x04, 0x00, 0x54,
	0x06, 0x14, 0x40, 0x38, 0x26, 0x14, 0x00, 0x38, 0x84, 0x04, 0x00, 0xd1,
	0xa4, 0xff, 0xff, 0xb5, 0xbf, 0x00, 0x00, 0x71, 0x00, 0x00, 0x42, 0xfa,
	0x22, 0x04, 0x00, 0x54, 0xe4, 0x03, 0x05, 0x2a, 0x46, 0x00, 0x00, 0xcb,
	0xdf, 0x08, 0x00, 0xf1, 0x83, 0x03, 0x00, 0x54, 0x05, 0x14, 0x40, 0x38,
	0x06, 0x14, 0x40, 0x38, 0xc5, 0x1c, 0x18, 0x33, 0x05, 0x03, 0x00, 0x34,
	0x0d, 0x00, 0x00, 0x94, 0x84, 0x10, 0x00, 0xb1, 0xa2, 0x02, 0x00, 0x54,
	0x25, 0x00, 0x05, 0xeb, 0xa0, 0x20, 0x4e, 0xfa, 0x66, 0x00, 0x01, 0xcb,
	0xc0, 0x20, 0x44, 0xfa, 0x03, 0x02, 0x00, 0x54, 0xa6, 0x14, 0x40, 0x38,
	0x26, 0x14, 0x00, 0x38, 0x84, 0x04, 0x00, 0xd1, 0xa4, 0xff, 0xff, 0xb5,
	0xd5, 0xff, 0xff, 0x17, 0x9f, 0x3c, 0x00, 0x71, 0x01, 0x01, 0x00, 0x54,
	0x1f, 0x00, 0x02, 0xeb, 0xe2, 0x00, 0x00, 0x54, 0x06, 0x14, 0x40, 0x38,
	0x84, 0x00, 0x06, 0xab, 0x82, 0x00, 0x00, 0x54, 0xdf, 0xfc, 0x03, 0x71,
	0x40, 0xff, 0xff, 0x54, 0xc0, 0x03, 0x5f, 0xd6, 0xe1, 0x03, 0x0e, 0xaa,
	0x20, 0x00, 0x0e, 0xcb, 0xe0, 0x01, 0x5f, 0xd6, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41
};
static const size_t lz4dec_bin_len = 512;

#define FREE(ptr) { \
if (ptr) { \
free(ptr); \
ptr = NULL; \
} \
}

static inline uint64_t read_u64_le(const unsigned char *p)
{
	return (uint64_t)p[0] |
	((uint64_t)p[1] << 8) |
	((uint64_t)p[2] << 16) |
	((uint64_t)p[3] << 24) |
	((uint64_t)p[4] << 32) |
	((uint64_t)p[5] << 40) |
	((uint64_t)p[6] << 48) |
	((uint64_t)p[7] << 56);
}

static inline void write_u32_le(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value & 0xFFu);
	buf[1] = (uint8_t)((value >> 8) & 0xFFu);
	buf[2] = (uint8_t)((value >> 16) & 0xFFu);
	buf[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static inline void write_u64_le(uint8_t *buf, uint64_t value)
{
	buf[0] = (uint8_t)(value & 0xFFu);
	buf[1] = (uint8_t)((value >> 8) & 0xFFu);
	buf[2] = (uint8_t)((value >> 16) & 0xFFu);
	buf[3] = (uint8_t)((value >> 24) & 0xFFu);
	buf[4] = (uint8_t)((value >> 32) & 0xFFu);
	buf[5] = (uint8_t)((value >> 40) & 0xFFu);
	buf[6] = (uint8_t)((value >> 48) & 0xFFu);
	buf[7] = (uint8_t)((value >> 56) & 0xFFu);
}

static int lz4_compress_and_add_shc(const void *inbuf, const size_t insize, void **outbuf, size_t *outsize)
{
	void* buffer = NULL;
	if (insize > LZ4_MAX_INPUT_SIZE) {
		return -1;
	}
	
	size_t tmpsize = LZ4_COMPRESSBOUND(insize);
	void *tmpbuf = malloc(tmpsize);
	if (!tmpbuf) {
		return -2;
	}
	
	int outlen = LZ4_compress_HC(inbuf, tmpbuf, (int)insize, (int)tmpsize, LZ4HC_CLEVEL_MAX);
	if (!outlen) {
		FREE(tmpbuf);
		return -3;
	}
	if ((outlen + lz4dec_bin_len) > 0x80000) {
		FREE(tmpbuf);
		return -4;
	}
	
	buffer = malloc(outlen + lz4dec_bin_len);
	if (!buffer) {
		FREE(tmpbuf);
		if (outbuf) *outbuf = NULL;
		return -5;
	}
	memcpy(buffer, lz4dec_bin, lz4dec_bin_len);
	memcpy(buffer + lz4dec_bin_len, tmpbuf, outlen);
	FREE(tmpbuf);
	
	uint8_t* sizebuf = (uint8_t*)(buffer + (lz4dec_bin_len - 4));
	write_u32_le(sizebuf, outlen);
	
	if (outbuf) *outbuf = buffer;
	if (outsize) *outsize = outlen + 0x200;
	return 0;
}

static void patch_pongo(uint8_t* pongo, const size_t sz, int sigcheckPatch)
{
	const uint64_t magicval = 0x1337cafebabe4100uLL;
	uint64_t ipf_flag = IPF_NONE;
	if (sigcheckPatch) {
		ipf_flag |= IPF_SIG_CHECK_PATCH;
	}
	uint8_t* cur = pongo;
	const uint8_t* end = (uint8_t*)(pongo + sz - sizeof(uint64_t));
	while (cur <= end) {
		if (read_u64_le(cur) == magicval) {
			write_u64_le(cur, ipf_flag);
			break;
		}
		cur += sizeof(uint64_t);
	}
}

int send_pongo_image(struct idevicerestore_client_t* client)
{
	if (client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}
	
	void *PongoImage = NULL;
	size_t PongoSize = 0;
	
	size_t pongoRawSize = Pongo_bin_len;
	if (pongoRawSize > 0x100000) {
		error("Too large pongo bin");
		return -1;
	}
	void *pongoRawImage = malloc(pongoRawSize);
	if (!pongoRawImage) {
		error("malloc failed (%s)\n", strerror(errno));
		return -1;
	}
	memset(pongoRawImage, 0, pongoRawSize);
	memcpy(pongoRawImage, &Pongo_bin, pongoRawSize);
	
	patch_pongo(pongoRawImage, pongoRawSize, 1);
	
	if (lz4_compress_and_add_shc(pongoRawImage, pongoRawSize, (void*)&PongoImage, &PongoSize)) {
		error("lz4 failed\n");
		FREE(pongoRawImage);
		FREE(PongoImage);
		return -1;
	}
	
	info("Sending Pongo data (%d bytes)...\n", (int)PongoSize);
	if (irecv_send_pongo(client->dfu->client, PongoImage, PongoSize) != IRECV_E_SUCCESS) {
		error("Failed to send pongo image\n");
		FREE(pongoRawImage);
		FREE(PongoImage);
		return -1;
	}
	info("Pongo image sent\n");
	
	if (client->dfu != NULL) {
		if (client->dfu->client != NULL) {
			// unsubscribe dfu_progress_callback
			irecv_event_unsubscribe(client->dfu->client, IRECV_PROGRESS);
		}
	}
	// free dfu client
	dfu_client_free(client);
	
	FREE(pongoRawImage);
	FREE(PongoImage);
	return 0;
}

int pongo_shell(struct idevicerestore_client_t* idr_client,
				struct irecv_device *device,
				irecv_client_t *pclient,
				int g_just_boot_pongo,
				int is_tethered,
				unsigned int boot_delay)
{
	irecv_client_t client = *pclient;
	
	int pwn_seprom_state = 0;
	int catch = 0;
	uint8_t save[0x2000] = {};
	memset(&save, 0, 0x2000);
	const char *typestr = NULL;
	
	char* foundp = NULL;
	char* endp = NULL;
	int rv = 0;
	uint32_t r32 = 0;
	while (1) {
		char buf[0x2000] = {};
		uint32_t outpos = 0;
		uint8_t in_progress = 1;
		while (in_progress) {
			rv = irecv_usb_control_transfer_no_timeout_retval(client, 0xa1, 2, 0, 0, (unsigned char *)&in_progress, (uint32_t)sizeof(in_progress), &r32);
			if (rv == IRECV_E_SUCCESS) {
				rv = irecv_usb_control_transfer_no_timeout_retval(client, 0xa1, 1, 0, 0, (unsigned char *)(buf + outpos), 0x1000, &r32);
				if (rv == IRECV_E_SUCCESS) {
					if (catch) {
						if (idr_client->get_shc_block || idr_client->get_pte_block) {
							if (idr_client->get_shc_block) {
								typestr = "shcblock2";
							}
							else {
								typestr = "pteblock2";
							}
							foundp = (char*)strstr(buf + outpos, "DUMP2_DATA:");
							if (foundp) {
								endp = (char*)strstr(foundp, ":DUMP2_END");
								if (endp) {
									char* startptr = (char*)(foundp + 11);
									size_t payload_size = ((uintptr_t)endp - (uintptr_t)startptr)/2;
									if (payload_size > 0x2000) {
										error("dump_block: overflow\n");
										goto bad;
									}
									info("dump_block: size: %d bytes\n", (int)payload_size);
									debug("dump_block: found block string\n");
									if (hexparse(save, (char*)startptr, payload_size) != 0) {
										error("dump_block: bad string\n");
										goto bad;
									}
									
									{
										// save block
										char zfn[1024];
										if (idr_client->cache_dir) {
											strcpy(zfn, idr_client->cache_dir);
											strcat(zfn, "/block");
										} else {
											strcpy(zfn, "block");
										}
										mkdir_with_parents(zfn, 0755);
										snprintf(&zfn[0] + strlen(zfn), sizeof(zfn) - strlen(zfn), "/%" PRIu64 "-%s-%s-restore-%s.bin", idr_client->ecid, idr_client->device->product_type, idr_client->version, typestr);
										FILE *zf = fopen(zfn, "wb");
										if (!zf) {
											error("error opening %s\n", zfn);
											goto bad;
										}
										fwrite(save, payload_size, 1, zf);
										fflush(zf);
										fclose(zf);
										info("%s.bin saved to '%s'\n", typestr, zfn);
									}
									catch = 0;
									if (CURRENT_STAGE != SEND_RESET) {
										return 0;
									}
								}
							}
						}
					}
					outpos += r32;
					if (outpos > 0x1000) {
						memmove(buf, buf + outpos - 0x1000, 0x1000);
						outpos = 0x1000;
					}
				}
			}
			if (rv != IRECV_E_SUCCESS) {
				goto bad;
			}
		}
		rv = irecv_usb_control_transfer_no_timeout_retval(client, 0x21, 4, 0xffff, 0, NULL, 0, &r32);
		if (rv != IRECV_E_SUCCESS) {
			goto bad;
		}
		
#define CHECK_BUFFER(__buf, _name) { \
debug("checking %s\n", _name); \
if (!__buf) { \
error("%s buffer not allocated or not found.\n", _name); \
goto bad; \
} \
}
		
#define PONGO_SEND_BUFFER(_buf, _size, name) { \
CHECK_BUFFER(_buf, name); \
size_t _sz = _size; \
debug("setup bulk transfer (%d bytes)\n", (int)_size); \
rv = irecv_usb_control_transfer_no_timeout_retval(client, 0x21, 1, 0, 0, (unsigned char *)&_sz, 4, &r32); \
if (rv != IRECV_E_SUCCESS) { \
error("failed to setup bulk transfer for %s (%s)\n", name, irecv_strerror(rv)); \
goto bad; \
} \
debug("sending %s (%d bytes)\n", name, (int)_size); \
rv = irecv_pongo_send_buffer(client, _buf, _size, &r32); \
if (rv != IRECV_E_SUCCESS) { \
error("failed to send %s (%s)\n", name, irecv_strerror(rv)); \
goto bad; \
} \
info("sent %s (%d bytes)\n", name, (int)_size); \
}

#define PONGO_SEND_MSG(msg, name) { \
debug("sending msg (%s)\n", name); \
rv = irecv_usb_control_transfer_no_timeout_retval(client, 0x21, 3, 0, 0, (unsigned char *)msg, (uint32_t)(strlen(msg)), &r32); \
if (rv != IRECV_E_SUCCESS) { \
error("failed to send %s msg (%s)\n", name, irecv_strerror(rv)); \
goto bad; \
} \
info("sent %s msg\n", name); \
}
		if (pwn_seprom_state & 3) {
			pwn_seprom_state = 4;
		}
		
		if (CURRENT_STAGE == NONE) {
			CURRENT_STAGE = SEND_SEP_MODULE;
			// continue;
		}
		
		if (CURRENT_STAGE == SEND_SEP_MODULE) {
			PONGO_SEND_BUFFER(sep_racer_bin, sep_racer_bin_len, "sep_racer");
			CURRENT_STAGE = LOAD_SEP_MODULE;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_SEP_MODULE) {
			PONGO_SEND_MSG("modload\n", "modload");
			if (idr_client->get_shc_block) {
				CURRENT_STAGE = GET_SHC_BLOCK;
				continue;
			}
			if (idr_client->get_pte_block && !idr_client->sep_fwload_race) {
				CURRENT_STAGE = GET_PTE_BLOCK;
				continue;
			}
			if (g_just_boot_pongo) {
				if (!idr_client->get_pte_block) {
					return 0;
				}
				CURRENT_STAGE = SEND_APIGM4TICKET;
				continue;
			}
			CURRENT_STAGE = SET_XARGS;
			continue;
		}
		
		if (CURRENT_STAGE == GET_SHC_BLOCK) {
			PONGO_SEND_MSG("sep shc_get\n", "shc_get");
			CURRENT_STAGE = USB_TRANSFER_ERROR;
			catch = 1;
			continue;
		}
		
		if (CURRENT_STAGE == GET_PTE_BLOCK) {
			PONGO_SEND_MSG("sep pte_get\n", "pte_get");
			CURRENT_STAGE = USB_TRANSFER_ERROR;
			if (idr_client->sep_fwload_race) {
				CURRENT_STAGE = SEND_RESET;
			}
			catch = 1;
			continue;
		}
		
		if (CURRENT_STAGE == SET_XARGS) {
			if (idr_client->disable_serial_output) {
				// skip it
			}
			else {
				PONGO_SEND_MSG("sep xargsadd serial=3\n", "xargsadd");
			}
			CURRENT_STAGE = SEND_APIGM4TICKET;
			if (idr_client->sep_boot_tz0_race) {
				CURRENT_STAGE = SEND_PTE;
			}
			continue;
		}
		
		if (CURRENT_STAGE == SEND_PTE) {
			PONGO_SEND_BUFFER(idr_client->sep_shellcode_block, idr_client->sep_shellcode_block_len, "pte");
			CURRENT_STAGE = LOAD_PTE;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_PTE) {
			PONGO_SEND_MSG("sep pte\n", "pte");
			CURRENT_STAGE = PWN_SEPROM_PTE;
			continue;
		}
		
		if (CURRENT_STAGE == PWN_SEPROM_PTE) {
			pwn_seprom_state = 2;
			PONGO_SEND_MSG("sep pwn_pte\n", "pwn pte");
			
			if ((
				 idr_client->build_major == 14 ||
				 idr_client->build_major == 15 ||
				 idr_client->build_major == 16 ||
				 idr_client->build_major == 17 ||
				 idr_client->build_major == 18 ||
				 idr_client->build_major == 19 ||
				 idr_client->build_major == 20 ||
				 idr_client->build_major == 21 ||
				 idr_client->build_major == 22 ||
				 idr_client->build_major == 23
				 ) && is_tethered) {
				CURRENT_STAGE = SEND_KPF_TETHERED;
			}
			else if (idr_client->build_major == 14 && idr_client->need_asr_patch) {
				CURRENT_STAGE = SEND_KPF_TETHERED;
			}
			else if (idr_client->cryptex1_nonce_seed) {
				CURRENT_STAGE = SEND_CRYPTEX1_NONCE_SETTER;
			}
			else {
				CURRENT_STAGE = SEND_BOOTUX;
			}
			continue;
		}
		
		if (CURRENT_STAGE == SEND_APIGM4TICKET) {
			PONGO_SEND_BUFFER(idr_client->img4_manifest, idr_client->img4_manifest_len, "ApImg4Ticket");
			CURRENT_STAGE = LOAD_APIGM4TICKET;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_APIGM4TICKET) {
			PONGO_SEND_MSG("sep manifest\n", "ApImg4Ticket");
			CURRENT_STAGE = SEND_APIGM4TICKET_HASH;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_APIGM4TICKET_HASH) {
			PONGO_SEND_BUFFER(idr_client->img4_manifest_hash, idr_client->img4_manifest_hash_len, "ApImg4TicketHash");
			CURRENT_STAGE = LOAD_APIGM4TICKET_HASH;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_APIGM4TICKET_HASH) {
			PONGO_SEND_MSG("sep hash\n", "ApImg4TicketHash");
			CURRENT_STAGE = SEND_RSEP;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_RSEP) {
			PONGO_SEND_BUFFER(idr_client->rsep_img4, idr_client->rsep_img4_len, "RestoreSEP");
			CURRENT_STAGE = LOAD_RSEP;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_RSEP) {
			PONGO_SEND_MSG("sep sepfw\n", "RestoreSEP");
			CURRENT_STAGE = SEND_SEP_PAYLOAD;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_SEP_PAYLOAD) {
			PONGO_SEND_BUFFER(idr_client->sepi_im4p, idr_client->sepi_im4p_len, "SEP");
			CURRENT_STAGE = LOAD_SEP_PAYLOAD;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_SEP_PAYLOAD) {
			PONGO_SEND_MSG("sep payload\n", "SEP");
			if (idr_client->cpid == 0x8000 || idr_client->cpid == 0x8003 || idr_client->cpid == 0x8001) {
				CURRENT_STAGE = SEND_SHELLCODE;
			}
			else {
				CURRENT_STAGE = SET_SEP_FLAG;
			}
			continue;
		}
		
		if (CURRENT_STAGE == SEND_SHELLCODE) {
			PONGO_SEND_BUFFER(idr_client->sep_shellcode_block, idr_client->sep_shellcode_block_len, "shellcode");
			CURRENT_STAGE = LOAD_SHELLCODE;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_SHELLCODE) {
			PONGO_SEND_MSG("sep shcload\n", "shellcode");
			CURRENT_STAGE = SET_SEP_FLAG;
			continue;
		}
		
		if (CURRENT_STAGE == SET_SEP_FLAG) {
			if (idr_client->get_pte_block) {
				PONGO_SEND_MSG("sep sep_flag e\n", "sep_flag");
			}
			else {
				PONGO_SEND_MSG("sep sep_flag 7\n", "sep_flag");
			}
			CURRENT_STAGE = PWN_SEPROM;
			continue;
		}
		
		if (CURRENT_STAGE == PWN_SEPROM) {
			pwn_seprom_state = 1;
			PONGO_SEND_MSG("sep pwn\n", "pwn");
			if (idr_client->get_pte_block) {
				CURRENT_STAGE = GET_PTE_BLOCK;
				continue;
			}
			
			if ((
				 idr_client->build_major == 14 ||
				 idr_client->build_major == 15 ||
				 idr_client->build_major == 16 ||
				 idr_client->build_major == 17 ||
				 idr_client->build_major == 18 ||
				 idr_client->build_major == 19 ||
				 idr_client->build_major == 20 ||
				 idr_client->build_major == 21 ||
				 idr_client->build_major == 22 ||
				 idr_client->build_major == 23
				 ) && is_tethered) {
				CURRENT_STAGE = SEND_KPF_TETHERED;
			}
			else if (idr_client->build_major == 14 && idr_client->need_asr_patch) {
				CURRENT_STAGE = SEND_KPF_TETHERED;
			}
			else if (idr_client->cryptex1_nonce_seed) {
				CURRENT_STAGE = SEND_CRYPTEX1_NONCE_SETTER;
			}
			else {
				CURRENT_STAGE = SEND_BOOTUX;
			}
			continue;
		}
		
		if (CURRENT_STAGE == SEND_KPF_TETHERED) {
			PONGO_SEND_BUFFER(kpf_bin, kpf_bin_len, "uploadKpfModule");
			CURRENT_STAGE = LOAD_KPF_TETHERED;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_KPF_TETHERED) {
			PONGO_SEND_MSG("modload\n", "modload");
			CURRENT_STAGE = SET_KPF_TETHERED;
			continue;
		}
		
		if (CURRENT_STAGE == SET_KPF_TETHERED) {
			PONGO_SEND_MSG("tethered_flags 1\n", "setupKpfModule");
			CURRENT_STAGE = SEND_OVERLAY;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_OVERLAY) {
			if (idr_client->build_major == 14 || idr_client->build_major == 15) {
				PONGO_SEND_BUFFER(union_bin, union_bin_len, "uploadOverlay");
			}
			else {
				PONGO_SEND_BUFFER(overlay_bin, overlay_bin_len, "uploadOverlay");
			}
			CURRENT_STAGE = LOAD_OVERLAY;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_OVERLAY) {
			PONGO_SEND_MSG("overlay-tethered\n", "overlay");
			CURRENT_STAGE = EXEC_KPF_TETHERED;
			continue;
		}
		
		if (CURRENT_STAGE == EXEC_KPF_TETHERED) {
			PONGO_SEND_MSG("kpf-tethered\n", "kpf");
			
			if (idr_client->cryptex1_nonce_seed) {
				CURRENT_STAGE = SEND_CRYPTEX1_NONCE_SETTER;
			}
			else {
				CURRENT_STAGE = SEND_BOOTUX;
			}
			continue;
		}
		
		if (CURRENT_STAGE == SEND_CRYPTEX1_NONCE_SETTER) {
			PONGO_SEND_BUFFER(cpf_bin, cpf_bin_len, "uploadCpfModule");
			CURRENT_STAGE = LOAD_CRYPTEX1_NONCE_SETTER;
			continue;
		}
		
		if (CURRENT_STAGE == LOAD_CRYPTEX1_NONCE_SETTER) {
			PONGO_SEND_MSG("modload\n", "modload");
			CURRENT_STAGE = SET_CRYPTEX1_NONCE_SEED;
			continue;
		}
		
		if (CURRENT_STAGE == SET_CRYPTEX1_NONCE_SEED) {
			char str[128];
			char _str[128];
			memset(&str, 0, 128);
			memset(&_str, 0, 128);
			sprintf(str, "cnch_seed %s\n", idr_client->cryptex1_nonce_seed);
			sprintf(_str, "cnch_seed %s", idr_client->cryptex1_nonce_seed);
			PONGO_SEND_MSG(str, _str);
			CURRENT_STAGE = SEND_CRYPTEX1_NONCE_SEED_PATCH;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_CRYPTEX1_NONCE_SEED_PATCH) {
			PONGO_SEND_MSG("cpf\n", "cpf");
			CURRENT_STAGE = SEND_BOOTUX;
			continue;
		}
		
		if (CURRENT_STAGE == SEND_BOOTUX) {
			if (boot_delay != 0) {
				sleep(boot_delay);
			}
			rv = irecv_usb_control_transfer_no_timeout_retval(client, 0x21, 3, 0, 0, (unsigned char *)"bootux\n", (uint32_t)(strlen("bootux\n")), &r32);
			info("sent bootux\n");
			return 0;
		}
		
		if (CURRENT_STAGE == SEND_RESET) {
			PONGO_SEND_MSG("reset\n", "reset");
			return 0;
		}
		
		if (CURRENT_STAGE == USB_TRANSFER_ERROR) {
		bad:
			if (pwn_seprom_state & 3) {
				error("maybe SEPROM pwn fail?\n");
			}
			error("usb transfer error\n");
			return -1;
		}
	}
	
	return 0;
}
