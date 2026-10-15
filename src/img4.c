/*
 * img4.c
 * Functions for handling the IMG4 format
 *
 * Copyright (c) 2013-2019 Nikias Bassen. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <string.h>

#include <libtatsu/tss.h>

#ifdef HAVE_TURDUS_MERULA
#include <libimobiledevice-glue/sha.h>
#include <libDER/libDER_config.h>
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>
#include <libDER/asn1Types.h>
#if (__linux__)
#include <arpa/inet.h>
#endif
#endif

#include "common.h"
#include "img4.h"
#include "endianness.h"

#define _ASN1_PRIVATE 0xc0
#define _ASN1_PRIMITIVE_TAG 0x1f
#define _ASN1_CONSTRUCTED 0x20
#define _ASN1_SEQUENCE 0x10
#define _ASN1_SET 0x11
#define _ASN1_CONTEXT_SPECIFIC 0x80
#define _ASN1_IA5_STRING 0x16
#define _ASN1_OCTET_STRING 0x04
#define _ASN1_INTEGER 0x02
#define _ASN1_BOOLEAN 0x01

#define IMG4_MAGIC "IMG4"
#define IMG4_MAGIC_SIZE 4

static int asn1_calc_int_size(uint64_t value)
{
	int i = 1;
	while ((value >>= 7) != 0) i++;
	return i;
}

static void asn1_write_int_value(unsigned char **p, uint64_t value, int size)
{
	int value_size = (size > 0) ? size : asn1_calc_int_size(value);
	int i = 0;
	for (i = 1; i <= value_size; i++) {
		(*p)[value_size-i] = value & 0xFF;
		value >>= 8;
	}
	*p += value_size;
}

static void asn1_write_size(unsigned int size, unsigned char** data, unsigned int *data_size)
{
	unsigned int off = 0;

	// first, calculate the size
	if (size >= 0x1000000) {
		// 1+4 bytes length
		(*data)[off++] = 0x84;
		(*data)[off++] = (size >> 24) & 0xFF;
		(*data)[off++] = (size >> 16) & 0xFF;
		(*data)[off++] = (size >> 8) & 0xFF;
		(*data)[off++] = size & 0xFF;
	} else if (size >= 0x10000) {
		// 1+3 bytes length
		(*data)[off++] = 0x83;
		(*data)[off++] = (size >> 16) & 0xFF;
		(*data)[off++] = (size >> 8) & 0xFF;
		(*data)[off++] = size & 0xFF;
	} else if (size >= 0x100) {
		// 1+2 bytes length
		(*data)[off++] = 0x82;
		(*data)[off++] = (size >> 8) & 0xFF;
		(*data)[off++] = (size & 0xFF);
	} else if (size >= 0x80) {
		// 1+1 byte length
		(*data)[off++] = 0x81;
		(*data)[off++] = (size & 0xFF);
	} else {
		// 1 byte length
		(*data)[off++] = size & 0xFF;
	}

	*data += off;
	*data_size += off;
}

static void asn1_write_element_header(unsigned char type, unsigned int size, unsigned char** data, unsigned int *data_size)
{
	unsigned int off = 0;

	if (!type || size == 0 || !data || !data_size) {
		return;
	}

	(*data)[off++] = type;
	*data += off;

	asn1_write_size(size, data, &off);

	*data_size += off;
}

static unsigned char* asn1_create_element_header(unsigned char type, unsigned int size, unsigned char** data, unsigned int *data_size)
{
	unsigned char buf[6];
	unsigned int off = 0;

	if (!type || size == 0 || !data || !data_size) {
		return NULL;
	}

	buf[off++] = type;

	unsigned char* p = &buf[off];
	asn1_write_size(size, &p, &off);

	*data = malloc(off);
	memcpy(*data, buf, off);
	*data_size = off;

	return *data;
}

static void asn1_write_priv_element(unsigned char **p, unsigned int *length, unsigned int value)
{
	int i = 0;
	int ttag = 0;
	int tag = value;

	i = _ASN1_CONSTRUCTED;
	i |= (0xFF & _ASN1_PRIVATE);

	(*p)[0] = i | _ASN1_PRIMITIVE_TAG;
	*p += 1;
	*length += 1;

	for (i = 0, ttag = tag; ttag > 0; i++)
            ttag >>= 7;
        ttag = i;
        while (i-- > 0) {
            (*p)[i] = tag & 0x7f;
            if (i != (ttag - 1))
                (*p)[i] |= 0x80;
            tag >>= 7;
        }
        *p += ttag;
	*length += ttag;
}

static void asn1_write_element(unsigned char **p, unsigned int *length, unsigned char type, void *data, int data_len)
{
	unsigned int this_len = 0;
	switch (type) {
	case _ASN1_IA5_STRING: {
		char *str = (char*)data;
		size_t len = (data_len < 0) ? strlen(str) : data_len;
		asn1_write_element_header(type, len, p, &this_len);
		*length += this_len;
		memcpy(*p, str, len);
		*p += len;
		*length += len;
	}	break;
	case _ASN1_OCTET_STRING: {
		asn1_write_element_header(type, data_len, p, &this_len);
		*length += this_len;
		memcpy(*p, data, data_len);
		*p += data_len;
		*length += data_len;
	}	break;
	case _ASN1_INTEGER: {
		uint64_t value = *(uint64_t*)data;
		int value_size = asn1_calc_int_size(value);
		asn1_write_element_header(type, value_size, p, &this_len);
		*length += this_len;
		asn1_write_int_value(p, value, value_size);
		*length += value_size;
	}	break;
	case _ASN1_BOOLEAN: {
		unsigned int value = *(unsigned int*)data;
		asn1_write_element_header(type, 1, p, &this_len);
		*length += this_len;
		asn1_write_int_value(p, value ? 0xFF : 0x00, 1);
		*length += 1;
	}	break;
	case (_ASN1_SET | _ASN1_CONSTRUCTED): {
		asn1_write_element_header(type, data_len, p, &this_len);
		*length += this_len;
		if (data && data_len > 0) {
			memcpy(*p, data, data_len);
			*p += data_len;
			*length += data_len;
		}
	}	break;
	default:
		fprintf(stderr, "ERROR: %s: type %02x is not implemented\n", __func__, type);
		return;
	}
}

static unsigned int asn1_get_element(const unsigned char* data, unsigned char* type, unsigned char* size)
{
	unsigned int off = 0;

	if (!data)
		return 0;

	if (type)
		*type = data[off++];
	if (size)
		*size = data[off++];

	return off;
}

static const unsigned char *asn1_find_element(unsigned int index, unsigned char type, const unsigned char* data)
{
	unsigned char el_type = 0;
	unsigned char el_size = 0;
	unsigned int off = 0;
	int i;

	// verify data integrity
	if (data[off++] != (_ASN1_CONSTRUCTED | _ASN1_SEQUENCE))
		return NULL;

	// check data size
	switch (data[off++]) {
	case 0x84:
		off += 4;
		break;
	case 0x83:
		off += 3;
		break;
	case 0x82:
		off += 2;
		break;
	case 0x81:
		off += 1;
		break;
	default:
		break;
	}

	// find the element we are searching
	for (i = 0; i <= index; i++) {
		off += asn1_get_element(&data[off], &el_type, &el_size);
		if (i == index)
			break;
		off += el_size;
	}

	// check element type
	if (el_type != type)
		return NULL;

	return &data[off];
}

static const char *_img4_get_component_tag(const char *compname)
{
	struct comp_tags {
		const char *comp;
		const char *tag;
	};
	const struct comp_tags component_tags[] = {
		{ "ACIBT", "acib" },
		{ "ACIBTLPEM", "lpbt" },
		{ "ACIWIFI", "aciw" },
		{ "ANE", "anef" },
		{ "ANS", "ansf" },
		{ "AOP", "aopf" },
		{ "AVE", "avef" },
		{ "Alamo", "almo" },
		{ "Ap,ANE1", "ane1" },
		{ "Ap,ANE2", "ane2" },
		{ "Ap,ANE3", "ane3" },
		{ "Ap,AudioAccessibilityBootChime", "auac" },
		{ "Ap,AudioBootChime", "aubt" },
		{ "Ap,AudioPowerAttachChime", "aupr" },
		{ "Ap,BootabilityBrainTrustCache", "trbb" },
		{ "Ap,CIO", "ciof" },
		{ "Ap,HapticAssets", "hpas" },
		{ "Ap,LocalBoot", "lobo" },
		{ "Ap,LocalPolicy", "lpol" },
		{ "Ap,NextStageIM4MHash", "nsih" },
		{ "Ap,RecoveryOSPolicyNonceHash", "ronh" },
		{ "Ap,RestoreANE1", "ran1" },
		{ "Ap,RestoreANE2", "ran2" },
		{ "Ap,RestoreANE3", "ran3" },
		{ "Ap,RestoreCIO", "rcio" },
		{ "Ap,RestoreTMU", "rtmu" },
		{ "Ap,Scorpius", "scpf" },
		{ "Ap,SystemVolumeCanonicalMetadata", "msys" },
		{ "Ap,TMU", "tmuf" },
		{ "Ap,VolumeUUID", "vuid" },
		{ "Ap,rOSLogo1", "rlg1" },
		{ "Ap,rOSLogo2", "rlg2" },
		{ "AppleLogo", "logo" },
		{ "AudioCodecFirmware", "acfw" },
		{ "BatteryCharging", "glyC" },
		{ "BatteryCharging0", "chg0" },
		{ "BatteryCharging1", "chg1" },
		{ "BatteryFull", "batF" },
		{ "BatteryLow0", "bat0" },
		{ "BatteryLow1", "bat1" },
		{ "BatteryPlugin", "glyP" },
		{ "CFELoader", "cfel" },
		{ "CrownFirmware", "crwn" },
		{ "DCP", "dcpf" },
		{ "Dali", "dali" },
		{ "DeviceTree", "dtre" },
		{ "Diags", "diag" },
		{ "EngineeringTrustCache", "dtrs" },
		{ "ExtDCP", "edcp" },
		{ "GFX", "gfxf" },
		{ "Hamm", "hamf" },
		{ "Homer", "homr" },
		{ "ISP", "ispf" },
		{ "InputDevice", "ipdf" },
		{ "KernelCache", "krnl" },
		{ "LLB", "illb" },
		{ "LeapHaptics", "lphp" },
		{ "Liquid", "liqd" },
		{ "LoadableTrustCache", "ltrs" },
		{ "LowPowerWallet0", "lpw0" },
		{ "LowPowerWallet1", "lpw1" },
		{ "LowPowerWallet2", "lpw2" },
		{ "MacEFI", "mefi" },
		{ "MtpFirmware", "mtpf" },
		{ "Multitouch", "mtfw" },
		{ "NeedService", "nsrv" },
		{ "OS", "OS\0\0" },
		{ "OSRamdisk", "osrd" },
		{ "PEHammer", "hmmr" },
		{ "PERTOS", "pert" },
		{ "PHLEET", "phlt" },
		{ "PMP", "pmpf" },
		{ "PersonalizedDMG", "pdmg" },
		{ "RBM", "rmbt" },
		{ "RTP", "rtpf" },
		{ "Rap,SoftwareBinaryDsp1", "sbd1" },
		{ "Rap,RTKitOS", "rkos" },
		{ "Rap,RestoreRTKitOS", "rrko" },
		{ "RecoveryMode", "recm" },
		{ "RestoreANS", "rans" },
		{ "RestoreDCP", "rdcp" },
		{ "RestoreDeviceTree", "rdtr" },
		{ "RestoreExtDCP", "recp" },
		{ "RestoreKernelCache", "rkrn" },
		{ "RestoreLogo", "rlgo" },
		{ "RestoreRTP", "rrtp" },
		{ "RestoreRamDisk", "rdsk" },
		{ "RestoreSEP", "rsep" },
		{ "RestoreTrustCache", "rtsc" },
		{ "SCE", "scef" },
		{ "SCE1Firmware", "sc1f" },
		{ "SEP", "sepi" },
		{ "SIO", "siof" },
		{ "StaticTrustCache", "trst" },
		{ "SystemLocker", "lckr" },
		{ "SystemVolume", "isys" },
		{ "WCHFirmwareUpdater", "wchf" },
		{ "ftap", "ftap" },
		{ "ftsp", "ftsp" },
		{ "iBEC", "ibec" },
		{ "iBSS", "ibss" },
		{ "iBoot", "ibot" },
		{ "iBootData", "ibdt" },
		{ "iBootDataStage1", "ibd1" },
		{ "iBootTest", "itst" },
		{ "rfta", "rfta" },
		{ "rfts", "rfts" },
		//{ "iBootTethered", "rlgo" },
		{ NULL, NULL }
	};
	int i = 0;

	while (component_tags[i].comp) {
		if (!strcmp(component_tags[i].comp, compname)) {
			return component_tags[i].tag;
		}
		i++;
	}

	return NULL;
}

int img4_stitch_component(const char* component_name, const unsigned char* component_data, unsigned int component_size, plist_t parameters, plist_t tss_response, unsigned char** img4_data, unsigned int *img4_size)
{
	unsigned char* magic_header = NULL;
	unsigned int magic_header_size = 0;
	unsigned char* blob_header = NULL;
	unsigned int blob_header_size = 0;
	unsigned char* img4header = NULL;
	unsigned int img4header_size = 0;
	unsigned int content_size;
	unsigned char* outbuf;
	unsigned char* p;
	unsigned char* blob = NULL;
	unsigned int blob_size = 0;

	if (!component_name || !component_data || component_size == 0 || !tss_response || !img4_data || !img4_size) {
		return -1;
	}

	if (tss_response_get_ap_img4_ticket(tss_response, &blob, &blob_size) != 0) {
		error("ERROR: %s: Failed to get ApImg4Ticket from TSS response\n", __func__);
		return -1;
	}

	info("Personalizing IMG4 component %s...\n", component_name);
	/* first we need check if we have to change the tag for the given component */
	const void *tag = asn1_find_element(1, _ASN1_IA5_STRING, component_data);
	if (tag) {
		debug("Tag found\n");
		if (strcmp(component_name, "RestoreKernelCache") == 0) {
			memcpy((void*)tag, "rkrn", 4);
		} else if (strcmp(component_name, "RestoreDeviceTree") == 0) {
			memcpy((void*)tag, "rdtr", 4);
		} else if (strcmp(component_name, "RestoreSEP") == 0) {
			memcpy((void*)tag, "rsep", 4);
		} else if (strcmp(component_name, "RestoreLogo") == 0) {
			memcpy((void*)tag, "rlgo", 4);
		} else if (strcmp(component_name, "RestoreTrustCache") == 0) {
			memcpy((void*)tag, "rtsc", 4);
		} else if (strcmp(component_name, "RestoreDCP") == 0) {
			memcpy((void*)tag, "rdcp", 4);
		} else if (strcmp(component_name, "Ap,RestoreTMU") == 0) {
			memcpy((void*)tag, "rtmu", 4);
		} else if (strcmp(component_name, "Ap,RestoreCIO") == 0) {
			memcpy((void*)tag, "rcio", 4);
		} else if (strcmp(component_name, "Ap,DCP2") == 0) {
			memcpy((void*)tag, "dcp2", 4);
		} else if (strcmp(component_name, "Ap,RestoreSecureM3Firmware") == 0) {
			memcpy((void*)tag, "rsm3", 4);
		} else if (strcmp(component_name, "Ap,RestoreSecurePageTableMonitor") == 0) {
			memcpy((void*)tag, "rspt", 4);
		} else if (strcmp(component_name, "Ap,RestoreTrustedExecutionMonitor") == 0) {
			memcpy((void*)tag, "rtrx", 4);
		} else if (strcmp(component_name, "Ap,RestorecL4") == 0) {
			memcpy((void*)tag, "rxcl", 4);
		} else if (strcmp(component_name, "iBootTethered") == 0) {
			memcpy((void*)tag, "rlgo", 4);
		} else if (strcmp(component_name, "iBootTethered2") == 0) {
			memcpy((void*)tag, "ibss", 4);
		} else if (strcmp(component_name, "iBoot32Tethered") == 0) {
			memcpy((void*)tag, "ibob", 4);
		} else if (strcmp(component_name, "SEPTethered") == 0) {
			memcpy((void*)tag, "sepi", 4);
		}
	}

	// check if we have a *-TBM entry for the given component
	unsigned char *additional_data = NULL;
	unsigned int additional_size = 0;
	char *tbm_key = malloc(strlen(component_name) + 5);
	snprintf(tbm_key, strlen(component_name)+5, "%s-TBM", component_name);
	plist_t tbm_dict = plist_dict_get_item(tss_response, tbm_key);
	free(tbm_key);
	uint64_t ucon_size = 0;
	const char* ucon_data = NULL;
	uint64_t ucer_size = 0;
	const char* ucer_data = NULL;
	if (tbm_dict) {
		plist_t dt = plist_dict_get_item(tbm_dict, "ucon");
		if (!dt) {
			error("ERROR: %s: Missing ucon node in %s-TBM dictionary\n", __func__, component_name);
			return -1;
		}
		ucon_data = plist_get_data_ptr(dt, &ucon_size);
		if (!ucon_data) {
			error("ERROR: %s: Missing ucon data in %s-TBM dictionary\n", __func__, component_name);
			return -1;
		}
		dt = plist_dict_get_item(tbm_dict, "ucer");
		if (!dt) {
			error("ERROR: %s: Missing ucer data node in %s-TBM dictionary\n", __func__, component_name);
			return -1;
		}
		ucer_data = plist_get_data_ptr(dt, &ucer_size);
		if (!ucer_data) {
			error("ERROR: %s: Missing ucer data in %s-TBM dictionary\n", __func__, component_name);
			return -1;
		}
	}

	int nonce_slot_required = plist_dict_get_bool(parameters, "RequiresNonceSlot") && (!strcmp(component_name, "SEP") || !strcmp(component_name, "SepStage1") || !strcmp(component_name, "LLB"));

	if (ucon_data || ucer_data || nonce_slot_required) {
		size_t im4r_size = 16;
		if (ucon_data) {
			im4r_size += 8 + 8 + ucon_size + 16;
		}
		if (ucer_data) {
			im4r_size += 8 + 8 + ucer_size + 16;
		}
		if (nonce_slot_required) {
			im4r_size += 16;
		}
		unsigned char *im4rset = (unsigned char*)malloc(im4r_size);
		unsigned char *p_im4rset = im4rset;
		unsigned int im4rlen = 0;

		// ----------- anid/snid -------
		if (nonce_slot_required) {
			const char* tag_name = NULL;
			uint64_t tag_value = 0;
			if (!strcmp(component_name, "SEP") || !strcmp(component_name, "SepStage1")) {
				tag_name = "snid";
				tag_value = 2;
				if (plist_dict_get_item(parameters, "SepNonceSlotID")) {
					tag_value = plist_dict_get_uint(parameters, "SepNonceSlotID");
				}
			} else {
				tag_name = "anid";
				tag_value = 0;
				if (plist_dict_get_item(parameters, "ApNonceSlotID")) {
					tag_value = plist_dict_get_uint(parameters, "ApNonceSlotID");
				}
			}
			// write priv anid/snid element
			asn1_write_priv_element(&p_im4rset, &im4rlen, __bswap_32(*(uint32_t*)tag_name));
			// write anid/snid IA5STRING and anid/snid value
			unsigned char inner_seq[16];
			unsigned char *p_inner_seq = &inner_seq[0];
			unsigned int inner_seq_hdr_len = 0;
			asn1_write_element(&p_inner_seq, &inner_seq_hdr_len, _ASN1_IA5_STRING, (void*)tag_name, -1);
			asn1_write_element(&p_inner_seq, &inner_seq_hdr_len, _ASN1_INTEGER, (void*)&tag_value, -1);

			// write anid/snid sequence
			unsigned char elem_seq[8];
			unsigned char *p = &elem_seq[0];
			unsigned int seq_hdr_len = 0;
			asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_seq_hdr_len, &p, &seq_hdr_len);

			// add size to priv anid/snid element
			asn1_write_size(inner_seq_hdr_len + seq_hdr_len, &p_im4rset, &im4rlen);

			// put it together
			memcpy(p_im4rset, elem_seq, seq_hdr_len);
			p_im4rset += seq_hdr_len;
			im4rlen += seq_hdr_len;
			memcpy(p_im4rset, inner_seq, inner_seq_hdr_len);
			p_im4rset += inner_seq_hdr_len;
			im4rlen += inner_seq_hdr_len;
		}

		// ----------- ucon ------------
		if (ucon_data) {
			// write priv ucon element
			asn1_write_priv_element(&p_im4rset, &im4rlen, *(uint32_t*)"nocu");

			// write ucon IA5STRING and ucon data header
			unsigned char inner_seq[16];
			unsigned char *p_inner_seq = &inner_seq[0];
			unsigned int inner_seq_hdr_len = 0;
			asn1_write_element(&p_inner_seq, &inner_seq_hdr_len, _ASN1_IA5_STRING, (void*)"ucon", -1);
			asn1_write_element_header(_ASN1_OCTET_STRING, ucon_size, &p_inner_seq, &inner_seq_hdr_len);

			// write ucon sequence
			unsigned char elem_seq[8];
			unsigned char *p = &elem_seq[0];
			unsigned int seq_hdr_len = 0;
			asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_seq_hdr_len + ucon_size, &p, &seq_hdr_len);

			// add size to priv ucon element
			asn1_write_size(inner_seq_hdr_len + ucon_size + seq_hdr_len, &p_im4rset, &im4rlen);

			// put it together
			memcpy(p_im4rset, elem_seq, seq_hdr_len);
			p_im4rset += seq_hdr_len;
			im4rlen += seq_hdr_len;
			memcpy(p_im4rset, inner_seq, inner_seq_hdr_len);
			p_im4rset += inner_seq_hdr_len;
			im4rlen += inner_seq_hdr_len;
			// write ucon data
			memcpy(p_im4rset, ucon_data, ucon_size);
			p_im4rset += ucon_size;
			im4rlen += ucon_size;
		}

		// ----------- ucer ------------
		if (ucer_data) {
			// write priv ucer element
			asn1_write_priv_element(&p_im4rset, &im4rlen, *(uint32_t*)"recu");

			// write ucer IA5STRING and ucer data header
			unsigned char inner_seq[16];
			unsigned char *p_inner_seq = &inner_seq[0];
			unsigned int inner_seq_hdr_len = 0;
			asn1_write_element(&p_inner_seq, &inner_seq_hdr_len, _ASN1_IA5_STRING, (void*)"ucer", -1);
			asn1_write_element_header(_ASN1_OCTET_STRING, ucer_size, &p_inner_seq, &inner_seq_hdr_len);

			// write ucer sequence
			unsigned char elem_seq[8];
			unsigned char *p = &elem_seq[0];
			unsigned int seq_hdr_len = 0;
			asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_seq_hdr_len + ucer_size, &p, &seq_hdr_len);

			// add size to priv ucer element
			asn1_write_size(inner_seq_hdr_len + ucer_size + seq_hdr_len, &p_im4rset, &im4rlen);

			// put it together
			memcpy(p_im4rset, elem_seq, seq_hdr_len);
			p_im4rset += seq_hdr_len;
			im4rlen += seq_hdr_len;
			memcpy(p_im4rset, inner_seq, inner_seq_hdr_len);
			p_im4rset += inner_seq_hdr_len;
			im4rlen += inner_seq_hdr_len;
			// write ucer data
			memcpy(p_im4rset, ucer_data, ucer_size);
			p_im4rset += ucer_size;
			im4rlen += ucer_size;
		}

		// now construct IM4R

		/* write inner set */
		unsigned char inner_set_[8];
		unsigned char *inner_set = &inner_set_[0];
		unsigned int inner_set_len = 0;
		asn1_write_element_header(_ASN1_SET | _ASN1_CONSTRUCTED, im4rlen, &inner_set, &inner_set_len);

		/* write header values */
		unsigned char hdrdata_[16];
		unsigned char *hdrdata = &hdrdata_[0];
		unsigned int hdrdata_len = 0;
		asn1_write_element(&hdrdata, &hdrdata_len, _ASN1_IA5_STRING, (void*)"IM4R", -1);

		/* write sequence now that we know the entire size */
		unsigned char seq_[8];
		unsigned char *seq = &seq_[0];
		unsigned int seq_len = 0;
		asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, im4rlen + inner_set_len + hdrdata_len, &seq, &seq_len);

		/* write outer cont[1] */
		unsigned char cont_[8];
		unsigned char *cont = &cont_[0];
		unsigned int cont_len = 0;
		asn1_write_element_header(_ASN1_CONTEXT_SPECIFIC | _ASN1_CONSTRUCTED | 1, im4rlen + inner_set_len + hdrdata_len + seq_len, &cont, &cont_len);

		// now put everything together
		additional_data = malloc(im4rlen + inner_set_len + hdrdata_len + seq_len + cont_len);
		p = additional_data;
		memcpy(p, cont_, cont_len);
		p += cont_len;
		memcpy(p, seq_, seq_len);
		p += seq_len;
		memcpy(p, hdrdata_, hdrdata_len);
		p += hdrdata_len;
		memcpy(p, inner_set_, inner_set_len);
		p += inner_set_len;
		memcpy(p, im4rset, im4rlen);
		p += im4rlen;
		additional_size = (unsigned int)(p - additional_data);

		free(im4rset);
	}

	// create element header for the "IMG4" magic
	asn1_create_element_header(_ASN1_IA5_STRING, IMG4_MAGIC_SIZE, &magic_header, &magic_header_size);
	// create element header for the blob (ApImg4Ticket)
	asn1_create_element_header(_ASN1_CONTEXT_SPECIFIC|_ASN1_CONSTRUCTED, blob_size, &blob_header, &blob_header_size);

	// calculate the size for the final IMG4 file (asn1 sequence)
	content_size = magic_header_size + IMG4_MAGIC_SIZE + component_size + blob_header_size + blob_size + additional_size;

	// create element header for the final IMG4 asn1 blob
	asn1_create_element_header(_ASN1_SEQUENCE|_ASN1_CONSTRUCTED, content_size, &img4header, &img4header_size);

	outbuf = (unsigned char*)malloc(img4header_size + content_size);
	if (!outbuf) {
		if (magic_header) {
			free(magic_header);
		}
		if (blob_header) {
			free(blob_header);
		}
		if (img4header) {
			free(img4header);
		}
		free(additional_data);
		error("ERROR: out of memory when personalizing IMG4 component %s\n", component_name);
		return -1;
	}
	p = outbuf;

	// now put everything together
	memcpy(p, img4header, img4header_size);
	p += img4header_size;
	memcpy(p, magic_header, magic_header_size);
	p += magic_header_size;
	memcpy(p, IMG4_MAGIC, IMG4_MAGIC_SIZE);
	p += IMG4_MAGIC_SIZE;
	memcpy(p, component_data, component_size);
	p += component_size;
	memcpy(p, blob_header, blob_header_size);
	p += blob_header_size;
	memcpy(p, blob, blob_size);
	p += blob_size;
	if (additional_size) {
		memcpy(p, additional_data, additional_size);
		p += additional_size;
	}

	*img4_data = outbuf;
	*img4_size = (p - outbuf);

	if (magic_header) {
		free(magic_header);
	}
	if (blob_header) {
		free(blob_header);
	}
	if (img4header) {
		free(img4header);
	}
	free(additional_data);

	return 0;
}

#ifndef __bswap_32
#define __bswap_32(x) ((((x) & 0xFF000000) >> 24) \
                    | (((x) & 0x00FF0000) >> 8) \
                    | (((x) & 0x0000FF00) << 8) \
                    | (((x) & 0x000000FF) << 24))
#endif

static void _manifest_write_key_value(unsigned char **p, unsigned int *length, const char *tag, int type, void *value, int size)
{
	uint32_t utag = __bswap_32(*(uint32_t*)tag);
	asn1_write_priv_element(p, length, utag);

	unsigned char *start = *p;
	unsigned char *outer_start = *p + 5;
	unsigned char *inner_start = *p + 5 + 6;
	unsigned int inner_length = 0;
	asn1_write_element(&inner_start, &inner_length, _ASN1_IA5_STRING, (void*)tag, -1);
	asn1_write_element(&inner_start, &inner_length, type, value, size);

	unsigned int outer_length = 0;
	unsigned int this_length = 0;
	if (!value && size > 0) {
		asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_length + size, &outer_start, &outer_length);
		asn1_write_size(outer_length + inner_length + size, &start, &this_length);
	} else {
		asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_length, &outer_start, &outer_length);
		asn1_write_size(outer_length + inner_length, &start, &this_length);
	}

	memmove(start, outer_start - outer_length, outer_length);
	outer_start = start + outer_length;
	*length += this_length;
	*length += outer_length;

	memmove(outer_start, inner_start - inner_length, inner_length);
	*length += inner_length;

	*p += this_length + outer_length + inner_length;
}

static void _manifest_write_component(unsigned char **p, unsigned int *length, const char *tag, plist_t comp)
{
	uint32_t utag = __bswap_32(*(uint32_t*)tag);
	asn1_write_priv_element(p, length, utag);

	unsigned char *start = *p;
	unsigned char *outer_start = *p + 5;
	unsigned char *inner_start = *p + 5 + 6;
	unsigned int inner_length = 0;
	asn1_write_element(&inner_start, &inner_length, _ASN1_IA5_STRING, (void*)tag, -1);

	unsigned char tmp_[512] = { 0, };
	unsigned int tmp_len = 0;
	unsigned char *tmp = &tmp_[0];

	plist_t node = NULL;
	uint8_t boolval = 0;

	node = plist_dict_get_item(comp, "Digest");
	if (node) {
		uint64_t digest_len = 0;
		const char *digest = plist_get_data_ptr(node, &digest_len);
		if (digest_len > 0) {
			_manifest_write_key_value(&tmp, &tmp_len, "DGST", _ASN1_OCTET_STRING, (void*)digest, digest_len);
		}
	}

	node = plist_dict_get_item(comp, "Trusted");
	if (node) {
		boolval = 0;
		plist_get_bool_val(node, &boolval);
		unsigned int int_bool_val = boolval;
		_manifest_write_key_value(&tmp, &tmp_len, "EKEY", _ASN1_BOOLEAN, &int_bool_val, -1);
	}

	node = plist_dict_get_item(comp, "EPRO");
	if (node) {
		boolval = 0;
		plist_get_bool_val(node, &boolval);
		unsigned int int_bool_val = boolval;
		_manifest_write_key_value(&tmp, &tmp_len, "EPRO", _ASN1_BOOLEAN, &int_bool_val, -1);
	}

	node = plist_dict_get_item(comp, "ESEC");
	if (node) {
		boolval = 0;
		plist_get_bool_val(node, &boolval);
		unsigned int int_bool_val = boolval;
		_manifest_write_key_value(&tmp, &tmp_len, "ESEC", _ASN1_BOOLEAN, &int_bool_val, -1);
	}

	node = plist_dict_get_item(comp, "TBMDigests");
	if (node) {
		uint64_t datalen = 0;
		const char *data = plist_get_data_ptr(node, &datalen);
		const char *tbmtag = NULL;
		if (!strcmp(tag, "sepi")) {
			tbmtag = "tbms";
		} else if (!strcmp(tag, "rsep")) {
			tbmtag = "tbmr";
		}
		if (!tbmtag) {
			error("ERROR: Unexpected TMBDigests for comp '%s'\n", tag);
		} else {
			_manifest_write_key_value(&tmp, &tmp_len, tbmtag, _ASN1_OCTET_STRING, (void*)data, datalen);
		}
	}

	asn1_write_element_header(_ASN1_SET | _ASN1_CONSTRUCTED, tmp_len, &inner_start, &inner_length);
	memcpy(inner_start, tmp_, tmp_len);
	inner_start += tmp_len;
	inner_length += tmp_len;

	unsigned int outer_length = 0;
	asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_length, &outer_start, &outer_length);

	unsigned int this_length = 0;
	asn1_write_size(outer_length + inner_length, &start, &this_length);

	memmove(start, outer_start - outer_length, outer_length);

	outer_start = start + outer_length;
	*length += this_length;
	*length += outer_length;

	memmove(outer_start, inner_start - inner_length, inner_length);

	*length += inner_length;

	*p += this_length + outer_length + inner_length;
}

int img4_create_local_manifest(plist_t request, plist_t build_identity, plist_t* manifest)
{
	if (!request || !manifest) {
		return -1;
	}

	unsigned char *buf = calloc(1, 65536);
	unsigned char *p = buf;
	unsigned int length = 0;
	uint64_t uintval = 0;
	unsigned int boolval = 0;

	unsigned char tmp_[1024];
	unsigned char *tmp = &tmp_[0];
	unsigned int tmp_len = 0;

	/* write manifest properties */
	uintval = plist_dict_get_uint(request, "ApBoardID");
	_manifest_write_key_value(&tmp, &tmp_len, "BORD", _ASN1_INTEGER, &uintval, -1);

	uintval = 0;
	_manifest_write_key_value(&tmp, &tmp_len, "CEPO", _ASN1_INTEGER, &uintval, -1);

	uintval = plist_dict_get_uint(request, "ApChipID");
	_manifest_write_key_value(&tmp, &tmp_len, "CHIP", _ASN1_INTEGER, &uintval, -1);

	boolval = plist_dict_get_bool(request, "ApProductionMode");
	_manifest_write_key_value(&tmp, &tmp_len, "CPRO", _ASN1_BOOLEAN, &boolval, -1);

	boolval = 0;
	_manifest_write_key_value(&tmp, &tmp_len, "CSEC", _ASN1_BOOLEAN, &boolval, -1);

	uintval = plist_dict_get_uint(request, "ApSecurityDomain");
	_manifest_write_key_value(&tmp, &tmp_len, "SDOM", _ASN1_INTEGER, &uintval, -1);

	/* create manifest properties set */
	_manifest_write_key_value(&p, &length, "MANP", _ASN1_SET | _ASN1_CONSTRUCTED, tmp_, tmp_len);

	plist_t component_manifest = NULL;
	if (build_identity) {
		component_manifest = plist_dict_get_item(build_identity, "Manifest");
	}

	/* now write the components */
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(request, &iter);
	char *key = NULL;
	plist_t val = NULL;
	do {
		plist_dict_next_item(request, iter, &key, &val);
		if (val && plist_get_node_type(val) == PLIST_DICT) {
			const char *comp = NULL;
			/* check if component has Img4PayloadType */
			if (component_manifest) {
				plist_t img4_comp = plist_access_path(component_manifest, 3, key, "Info", "Img4PayloadType");
				if (img4_comp) {
					comp = plist_get_string_ptr(img4_comp, NULL);
				}
			}
			if (!comp) {
				comp = _img4_get_component_tag(key);
			}
			if (!comp) {
				debug("DEBUG: %s: Unhandled component '%s'\n", __func__, key);
				_manifest_write_component(&p, &length, key, val);
			} else {
				debug("DEBUG: found component %s (%s)\n", comp, key);
				_manifest_write_component(&p, &length, comp, val);
			}
		}
		free(key);
	} while (val);
	free(iter);

	/* write manifest body header */
	unsigned char manb_[32];
	unsigned char *manb = &manb_[0];
	unsigned int manb_len = 0;
	_manifest_write_key_value(&manb, &manb_len, "MANB", _ASN1_SET | _ASN1_CONSTRUCTED, NULL, length);

	/* write inner set */
	unsigned char inner_set_[8];
	unsigned char *inner_set = &inner_set_[0];
	unsigned int inner_set_len = 0;
	asn1_write_element_header(_ASN1_SET | _ASN1_CONSTRUCTED, length + manb_len, &inner_set, &inner_set_len);

	/* write header values */
	unsigned char hdrdata_[16];
	unsigned char *hdrdata = &hdrdata_[0];
	unsigned int hdrdata_len = 0;
	asn1_write_element(&hdrdata, &hdrdata_len, _ASN1_IA5_STRING, (void*)"IM4M", -1);
	uint64_t intval = 0;
	asn1_write_element(&hdrdata, &hdrdata_len, _ASN1_INTEGER, &intval, -1);

	/* write outer sequence now that we know the entire size */
	unsigned char seq_[8];
	unsigned char *seq = &seq_[0];
	unsigned int seq_len = 0;
	asn1_write_element_header(_ASN1_SEQUENCE | _ASN1_CONSTRUCTED, inner_set_len + length + manb_len + hdrdata_len, &seq, &seq_len);

	unsigned int header_len = seq_len + hdrdata_len + inner_set_len + manb_len;

	/* now put everything together */
	memmove(buf + header_len, buf, length);

	unsigned char *hdr = buf;
	unsigned int hdr_len = 0;

	memcpy(hdr, seq_, seq_len);
	hdr += seq_len;
	hdr_len += seq_len;

	memcpy(hdr, hdrdata_, hdrdata_len);
	hdr += hdrdata_len;
	hdr_len += hdrdata_len;

	memcpy(hdr, inner_set_, inner_set_len);
	hdr += inner_set_len;
	hdr_len += inner_set_len;

	memcpy(hdr, manb_, manb_len);
	hdr += manb_len;
	hdr_len += manb_len;

	length += hdr_len;

	*manifest = plist_new_data((char*)buf, length);

	free(buf);

	return 0;
}

#ifdef HAVE_TURDUS_MERULA
void img4_override_payload_tag(const char* component_name, const unsigned char* component_data)
{
	const void *tag = asn1_find_element(1, _ASN1_IA5_STRING, component_data);
	if (tag) {
		debug("Tag found\n");
		if (!strcmp(component_name, "RestoreKernelCache")) {
			memcpy((void*)tag, "rkrn", 4);
		}
		if (!strcmp(component_name, "RestoreDeviceTree")) {
			memcpy((void*)tag, "rdtr", 4);
		}
		if (!strcmp(component_name, "RestoreSEP")) {
			memcpy((void*)tag, "rsep", 4);
		}
		if (!strcmp(component_name, "RestoreLogo")) {
			memcpy((void*)tag, "rlgo", 4);
		}
		if (!strcmp(component_name, "RestoreTrustCache")) {
			memcpy((void*)tag, "rtsc", 4);
		}
	}
}

static int get_img4_payload_tag(const char* component_name, const unsigned char* component_data, uint32_t* rv)
{
	const uint32_t *tag = (const uint32_t *)asn1_find_element(1, _ASN1_IA5_STRING, component_data);
	if (tag) {
		debug("Tag found\n");
		*rv = ntohl(tag[0]);
		return 0;
	}
	return -1;
}

static int get_img4_type_tag(const char* component_name, uint32_t* rv)
{
	uint32_t tag = 0;
	const char* _tag = _img4_get_component_tag(component_name);
	if (_tag == NULL) {
		return -1;
	}
	
	memcpy((void*)&tag, _tag, 4);
	if (!strcmp(component_name, "OS")) {
		memcpy((void*)&tag, "rosi", 4);
	}
	*rv = ntohl(tag);
	return 0;
}

// xerub's img4lib
#define E000000000000000 (ASN1_CONSTRUCTED | ASN1_PRIVATE)
#define RESERVE_DIGEST_SPACE 20

typedef struct {
	DERItem item;
	DERTag tag;
} DERMonster;

typedef struct {
	DERItem magic;      // "IM4M"
	DERItem version;    // 0
	DERItem theset;     // MANB + MANP
	DERItem sig_blob;   // RSA
	DERItem chain_blob; // cert chain
	DERItem img4_blob;
	DERByte full_digest[RESERVE_DIGEST_SPACE];
	DERByte theset_digest[RESERVE_DIGEST_SPACE];
} TheImg4Manifest;

const DERItemSpec DERImg4ManifestItemSpecs[5] = {
	{ 0 * sizeof(DERItem), ASN1_IA5_STRING,                             0 },                    // "IM4M"
	{ 1 * sizeof(DERItem), ASN1_INTEGER,                                0 },                    // 0
	{ 2 * sizeof(DERItem), ASN1_CONSTR_SET,                             DER_DEC_SAVE_DER },     // SET(things)
	{ 3 * sizeof(DERItem), ASN1_OCTET_STRING,                           0 },                    // RSA
	{ 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE,                        0 }                     // chain
};

static int DERImg4DecodeFindInSequence(unsigned char *a1, unsigned char *a2, DERTag tag, DERItem *a5)
{
	DERDecodedInfo currDecoded;
	DERSequence derSeq;
	
	derSeq.nextItem = a1;
	derSeq.end = a2;
	
	do {
		int rv = DERDecodeSeqNext(&derSeq, &currDecoded);
		if (rv) {
			return rv;
		}
	} while (currDecoded.tag != tag);
	
	*a5 = currDecoded.content;
	return 0;
}

static int DERImg4DecodeContentFindItemWithTag(const DERItem *a1, DERTag tag, DERItem *a4)
{
	int rv;
	DERSequence derSeq;
	
	rv = DERDecodeSeqContentInit(a1, &derSeq);
	if (rv) {
		return rv;
	}
	return DERImg4DecodeFindInSequence(derSeq.nextItem, derSeq.end, tag, a4);
}

static int DERImg4DecodeTagCompare(const DERItem *a1, uint32_t nameTag)
{
	uint32_t var_14;
	
	if (a1->length < 4) {
		return -1;
	}
	if (a1->length > 4) {
		return 1;
	}
	
	if (DERParseInteger(a1, &var_14)) {
		return -2;
	}
	
	if (var_14 < nameTag) {
		return -1;
	}
	if (var_14 > nameTag) {
		return 1;
	}
	return 0;
}

static int DERImg4DecodeManifest(const DERItem *a1, TheImg4Manifest *a2)
{
	int rv;
	uint32_t var_14;
	
	if (a1 == NULL || a2 == NULL) {
		return DR_ParamErr;
	}
	if (a1->data == NULL || a1->length == 0) {
		return 0;
	}
	
	rv = DERParseSequence(a1, 5, DERImg4ManifestItemSpecs, a2, 0);
	if (rv) {
		return rv;
	}
	
	if (DERImg4DecodeTagCompare(&a2->magic, 'IM4M')) {
		return DR_UnexpectedTag;
	}
	
	rv = DERParseInteger(&a2->version, &var_14);
	if (rv) {
		return rv;
	}
	
	if (var_14) {
		return DR_UnexpectedTag;
	}
	return 0;
}

static int DERImg4DecodeProperty(const DERItem *a1, DERTag etag, DERMonster *a4)
{
	int rv;
	uint32_t var_6C;
	DERTag tag;
	DERSequence var_60;
	DERDecodedInfo var_50;
	DERDecodedInfo var_38;
	
	if (a1 == NULL || a4 == NULL) {
		return DR_ParamErr;
	}
	
	rv = DERDecodeSeqInit(a1, &tag, &var_60);
	if (rv) {
		return rv;
	}
	
	if (tag != ASN1_CONSTR_SEQUENCE) {
		return DR_UnexpectedTag;
	}
	
	rv = DERDecodeSeqNext(&var_60, &var_38);
	if (rv) {
		return rv;
	}
	
	if (var_38.tag != ASN1_IA5_STRING) {
		return DR_UnexpectedTag;
	}
	
	rv = DERParseInteger(&var_38.content, &var_6C);
	if (rv) {
		return rv;
	}
	
	if ((E000000000000000 | var_6C) != etag) {
		return DR_UnexpectedTag;
	}
	
	a4[0].item = var_38.content;
	
	rv = DERDecodeSeqNext(&var_60, &var_50);
	if (rv) {
		return rv;
	}
	
	a4[1].tag = var_50.tag;
	a4[1].item = var_50.content;
	
	rv = DERDecodeSeqNext(&var_60, &var_50);
	if (rv != DR_EndOfSequence) {
		return DR_UnexpectedTag;
	}
	return 0;
}

static int DERImg4DecodeFindProperty(const DERItem *a1, DERTag etag, DERTag atag, DERMonster *dest)
{
	int rv;
	DERItemSpec var_70[2];
	uint32_t var_3C;
	DERItem var_38;
	
	rv = DERImg4DecodeContentFindItemWithTag(a1, etag, &var_38);
	if (rv) {
		return rv;
	}
	
	var_70[0].offset = 0;
	var_70[0].tag = ASN1_IA5_STRING;
	var_70[0].options = 0;
	var_70[1].offset = sizeof(DERMonster);
	var_70[1].tag = atag;
	var_70[1].options = 0;
	
	rv = DERParseSequence(&var_38, 2, var_70, dest, 0);
	if (rv) {
		return rv;
	}
	
	rv = DERParseInteger(&dest[0].item, &var_3C);
	if (rv) {
		return rv;
	}
	
	if ((E000000000000000 | var_3C) != etag) {
		return DR_UnexpectedTag;
	}
	
	dest[0].tag = etag | E000000000000000;
	dest[1].tag = atag;
	return 0;
}

static int Img4DecodeGetPropertyData(const DERItem *a1, DERTag tag, DERByte **a4, DERSize *a5)
{
	int rv;
	DERItem var_50;
	DERMonster var_40[2];
	
	var_50.data = a1->data;
	var_50.length = a1->length;
	
	rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
	if (rv) {
		return rv;
	}
	
	if (var_40[1].tag != ASN1_OCTET_STRING) {
		return DR_UnexpectedTag;
	}
	
	*a4 = var_40[1].item.data;
	*a5 = var_40[1].item.length;
	return 0;
}

int Img4DecodeGetPropertyInteger64(const DERItem *a1, DERTag tag, uint64_t *value)
{
	int rv;
	DERItem var_50;
	DERMonster var_40[2];
	
	var_50.data = a1->data;
	var_50.length = a1->length;
	
	rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
	if (rv) {
		return rv;
	}
	
	if (var_40[1].tag != ASN1_INTEGER) {
		return DR_UnexpectedTag;
	}
	
	return DERParseInteger64(&var_40[1].item, value);
}

static int Img4ManifestGetDigest(const TheImg4Manifest *m, const unsigned int type, DERByte** hash, DERSize *hash_len)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, E000000000000000 | type, ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	objp = var_70[1].item;
	
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'DGST') {
			DERSize var_1C;
			DERByte *var_18;
			rv = Img4DecodeGetPropertyData(&var_68, var_48.tag, &var_18, &var_1C);
			if (rv) {
				return rv;
			}
			
			size_t _hash_len = var_1C;
			uint8_t* _hash = malloc(var_1C);
			if (!_hash) {
				error("ERROR: malloc failed\n");
				return -40;
			}
			memcpy(_hash, var_18, var_1C);
			var_18 = NULL;
			var_1C = 0;
			
			uint8_t* my_hash = (uint8_t*)_hash;
			debug("manifest DGST: ");
			for (int i = 0; i < _hash_len; i++) {
				debug("%02x", my_hash[i]);
			}
			debug("\n");
			
			if (hash) *hash = _hash;
			if (hash_len) *hash_len = _hash_len;
			return 0;
		}
		return -41;
	}
	return -42;
}

static int Img4ManifestGetBootNonceHash(const TheImg4Manifest *m, DERByte** hash, DERSize *hash_len)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;

	objp = manp;
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'BNCH') {
			DERSize var_1C;
			DERByte *var_18;
			rv = Img4DecodeGetPropertyData(&var_68, var_48.tag, &var_18, &var_1C);
			if (rv) {
				return rv;
			}
			
			size_t _hash_len = var_1C;
			uint8_t* _hash = malloc(var_1C);
			if (!_hash) {
				error("ERROR: malloc failed\n");
				return -40;
			}
			memcpy(_hash, var_18, var_1C);
			var_18 = NULL;
			var_1C = 0;
			
			uint8_t* my_hash = (uint8_t*)_hash;
			debug("manifest BNCH: ");
			for (int i = 0; i < _hash_len; i++) {
				debug("%02x", my_hash[i]);
			}
			debug("\n");
			
			if (hash) *hash = _hash;
			if (hash_len) *hash_len = _hash_len;
			return 0;
		}
	}
	return -42;
}

static int Img4ManifestGetECID(const TheImg4Manifest *m, uint64_t* ecid)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;
	
	objp = manp;
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'ECID') {
			uint64_t var_18 = 0;
			rv = Img4DecodeGetPropertyInteger64(&var_68, var_48.tag, &var_18);
			if (rv) {
				return rv;
			}
			debug("manifest ECID: %016" PRIx64 "\n", var_18);
			if (ecid) *ecid = var_18;
			return 0;
		}
	}
	return -42;
}

static int get_im4p_hash(struct idevicerestore_client_t* client, const char *compname,
						 const uint8_t* payload, const size_t payload_len,
						 uint8_t** hash, size_t* hash_len)
{
	uint8_t* _hash = NULL;
	size_t _hash_len = 0;
	
	if (client->cpid == 0x8010 || client->cpid == 0x8011) {
		unsigned char tsha384[SHA384_DIGEST_LENGTH];
		memset(tsha384, 0, SHA384_DIGEST_LENGTH);
		sha384_context sha384ctx;
		sha384_init(&sha384ctx);
		sha384_update(&sha384ctx, payload, payload_len);
		sha384_final(&sha384ctx, tsha384);
		_hash_len = SHA384_DIGEST_LENGTH;
		_hash = malloc(_hash_len);
		if (!_hash) {
			error("ERROR: malloc failed\n");
			return -1;
		}
		memset(_hash, 0, _hash_len);
		memcpy(_hash, tsha384, SHA384_DIGEST_LENGTH);
	}
	else if (client->cpid == 0x7000 || client->cpid == 0x7001 || client->cpid == 0x8000 || client->cpid == 0x8001 || client->cpid == 0x8003) {
		unsigned char tsha1[SHA1_DIGEST_LENGTH];
		memset(tsha1, 0, SHA1_DIGEST_LENGTH);
		sha1_context sha1ctx;
		sha1_init(&sha1ctx);
		sha1_update(&sha1ctx, payload, payload_len);
		sha1_final(&sha1ctx, tsha1);
		_hash_len = SHA1_DIGEST_LENGTH;
		_hash = malloc(_hash_len);
		if (!_hash) {
			error("ERROR: malloc failed\n");
			return -1;
		}
		memset(_hash, 0, _hash_len);
		memcpy(_hash, tsha1, SHA1_DIGEST_LENGTH);
	}
	else {
		error("ERROR: Found unknown device\n");
		return -1;
	}
	
	uint8_t* my_hash = (uint8_t*)_hash;
	debug("%s hash: ", compname);
	for (int i = 0; i < _hash_len; i++) {
		debug("%02x", my_hash[i]);
	}
	debug("\n");
	
	if (hash) *hash = _hash;
	if (hash_len) *hash_len = _hash_len;
	return 0;
}

int get_img4_digest_from_manifest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname,
								  const uint8_t* manifest, const size_t manifest_len, uint8_t** hash, size_t* hash_len)
{
	int rv = -16;
	
	if (!client || !build_identity || !compname || !manifest || !manifest_len) {
		return -16;
	}
	
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	uint32_t type = 0;
	
	if (!build_identity_has_component(build_identity, compname)) {
		rv = -17;
		goto err;
	}
	
	if (get_img4_type_tag(compname, &type)) {
		error("ERROR: Unable to get %s image4 type tag\n", compname);
		rv = -18;
		goto err;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		error("ERROR: Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
		info("Failed to get digest from image4 manifest\n");
		rv = 2;
		goto res;
	}
	
	rv = 0;
	
res:
	if (hash) *hash = mhash;
	if (hash_len) *hash_len = mhash_len;
err:
	return rv;
}

int get_boot_nonce_hash_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint8_t** boot_nonce_hash, size_t *nonce_hash_length)
{
	int rv = -16;
	
	if (!client || !manifest || !manifest_len) {
		return -16;
	}
	
	uint8_t* bhash = NULL;
	size_t bhash_len = 0;
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		error("ERROR: Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetBootNonceHash(&m, (DERByte **)&bhash, (DERSize *)&bhash_len)) {
		info("Failed to get boot-nonce hash from image4 manifest\n");
		rv = 2;
		goto res;
	}
	
	rv = 0;
	
res:
	if (boot_nonce_hash) *boot_nonce_hash = bhash;
	if (nonce_hash_length) *nonce_hash_length = bhash_len;
err:
	return rv;
}

int validate_boot_nonce_hash(struct idevicerestore_client_t* client)
{
	int rv = -1;
	if (!client) {
		return rv;
	}
	if (!client->nonce) {
		error("ERROR: no ApNonce\n");
		return rv;
	}
	
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint8_t* boot_nonce_hash = NULL;
	size_t nonce_hash_size = 0;
	
	tss_data = plist_copy(client->local_shsh);
	if (!tss_data) {
		error("ERROR: local TSS data not found\n");
		rv = -2;
		goto end;
	}
	
	plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
	if (!apimg4ticket) {
		error("ERROR: no ApImg4Ticket dict\n");
		rv = -3;
		goto end;
	}
	
	plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
	if (!im4m_data) {
		error("ERROR: no img4 manifest\n");
		rv = -4;
		goto end;
	}
	
	if (get_boot_nonce_hash_from_manifest(client, (const uint8_t*)im4m_data, (const size_t)im4m_data_len, &boot_nonce_hash, &nonce_hash_size)) {
		error("ERROR: Unable to get boot-nonce hash from manifest\n");
		rv = -5;
		goto end;
	}
	
	if (!boot_nonce_hash) {
		error("ERROR: no boot-nonce hash\n");
		rv = -6;
		goto end;
	}
	
	if (client->nonce_size != nonce_hash_size) {
		error("ERROR: wrong boot-nonce hash size (%d != %d)\n", client->nonce_size, (int)nonce_hash_size);
		rv = -7;
		goto end;
	}
	
	info("ApNonce: ");
	int i;
	for (i = 0; i < client->nonce_size; i++) {
		info("%02x", client->nonce[i]);
	}
	info("\n");
	info("BNCH: ");
	for (i = 0; i < nonce_hash_size; i++) {
		info("%02x", boot_nonce_hash[i]);
	}
	info("\n");
	
	if (memcmp(boot_nonce_hash, client->nonce, nonce_hash_size)) {
		error("ERROR: Unexpected boot-nonce hash\n");
		rv = -8;
		goto end;
	}
	
	rv = 0;
	
end:
	if (tss_data) plist_free(tss_data);
	if (im4m_data) free(im4m_data);
	if (boot_nonce_hash) free(boot_nonce_hash);
	return rv;
}

static int get_ECID_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint64_t* ecid)
{
	int rv = -16;
	
	if (!client || !manifest || !manifest_len) {
		return -16;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		error("ERROR: Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetECID(&m, ecid)) {
		info("Failed to get ECID from image4 manifest\n");
		rv = 2;
		goto err;
	}
	
	rv = 0;
	
err:
	return rv;
}

int validate_ECID(struct idevicerestore_client_t* client)
{
	int rv = -1;
	if (!client) {
		return rv;
	}
	if (!client->ecid) {
		error("ERROR: no ECID\n");
		return rv;
	}
	
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint64_t im4m_ecid = 0;
	tss_data = plist_copy(client->local_shsh);
	if (!tss_data) {
		error("ERROR: local TSS data not found\n");
		rv = -2;
		goto end;
	}
	
	plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
	if (!apimg4ticket) {
		error("ERROR: no ApImg4Ticket dict\n");
		rv = -3;
		goto end;
	}
	
	plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
	if (!im4m_data) {
		error("ERROR: no img4 manifest\n");
		rv = -4;
		goto end;
	}
	
	if (get_ECID_from_manifest(client, (const uint8_t*)im4m_data, (const size_t)im4m_data_len, &im4m_ecid)) {
		error("ERROR: Unable to get ECID from manifest\n");
		rv = -5;
		goto end;
	}
	
	info("Device ECID: %016" PRIx64 "\n", client->ecid);
	info("IM4M ECID: %016" PRIx64 "\n", im4m_ecid);
	
	if (client->ecid != im4m_ecid) {
		error("ERROR: ECID mismatch detected\n");
		rv = -8;
		goto end;
	}
	
	rv = 0;
	
end:
	if (tss_data) plist_free(tss_data);
	if (im4m_data) free(im4m_data);
	return rv;
}

int validate_img4_digest(struct idevicerestore_client_t* client, plist_t build_identity,
						 const char *compname, const uint8_t* payload, const size_t payload_len,
						 const uint8_t* manifest, const size_t manifest_len,
						 bool verify_manifest, bool verify_payload, uint32_t* result)
{
	int rv = -16;
	if (!client || !build_identity || !compname) {
		return -16;
	}
	
	uint32_t _result = IMG4_DIGEST_ERROR;
	
	uint8_t* digest = NULL;
	size_t digest_len = 0;
	uint8_t* hash = NULL;
	size_t hash_len = 0;
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	uint32_t type = 0;
	
	if (!build_identity_has_component(build_identity, compname)) {
		rv = -17;
		goto err;
	}
	
	if (build_identity_get_component_digest(build_identity, compname, &digest, &digest_len)) {
		error("ERROR: Unable to find digest data\n");
		rv = -18;
		goto err;
	}
	
	if (verify_payload) {
		if (!payload || !payload_len) {
			error("ERROR: Unable to find image4 payload\n");
			rv = -19;
			goto err;
		}
	}
	
	if (verify_manifest) {
		if (!manifest || !manifest_len) {
			error("ERROR: Unable to find image4 manifest\n");
			rv = -20;
			goto err;
		}
	}
	
	if (get_img4_type_tag(compname, &type)) {
		error("ERROR: Unable to get %s image4 type tag\n", compname);
		rv = -21;
		goto err;
	}
	
	// Here we check whether the digest hash in the ipsw's BuildManifest and the img4 payload match.
	if (verify_payload) {
		uint32_t _type = 0;
		if (get_img4_payload_tag(compname, payload, &_type)) {
			error("ERROR: Unable to get image4 payload type tag\n");
			rv = -22;
			goto err;
		}
		if (_type != type) {
			error("ERROR: image4 type tag does not match (%08x != %08x)\n", _type, type);
			rv = -23;
			goto err;
		}
		if (get_im4p_hash(client, compname, payload, payload_len, &hash, &hash_len)) {
			error("ERROR: Unable to get image4 payload hash\n");
			rv = -24;
			goto err;
		}
		if (hash_len != digest_len) {
			error("ERROR: Hash size does not match\n");
			rv = -25;
			goto err;
		}
		// check hash
		if (memcmp(digest, hash, digest_len)) {
			info("Hash does not match\n");
			_result |= IMG4_DIGEST_VALID_PAYLOAD;
		}
		else {
			_result |= (IMG4_DIGEST_VALID_PAYLOAD | IMG4_DIGEST_MATCHED_PAYLOAD);
		}
	}
	
	if (verify_manifest) {
		DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
		TheImg4Manifest m;
		if (DERImg4DecodeManifest(&tmp, &m)) {
			error("ERROR: Failed to decode image4 manifest\n");
			rv = -26;
			goto err;
		}
		
		if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
			info("Failed to get digest from image4 manifest\n");
			rv = 2;
			goto res;
		}
		
		if (mhash_len != digest_len) {
			error("ERROR: Hash size does not match\n");
			rv = -27;
			goto err;
		}
		if (memcmp(digest, mhash, digest_len)) {
			info("Hash does not match\n");
			_result |= IMG4_DIGEST_VALID_MANIFEST;
		}
		else {
			_result |= (IMG4_DIGEST_VALID_MANIFEST | IMG4_DIGEST_MATCHED_MANIFEST);
		}
	}
	
	rv = 0;
	
res:
	if (result) *result = _result;
	
err:
	if (digest) free(digest);
	if (hash) free(hash);
	if (mhash) free(mhash);
	return rv;
}

int get_image4_manifest_hash(const uint8_t* manifest, const size_t manifest_len, uint32_t type, uint8_t** hash, size_t* hash_len)
{
	int rv = -16;
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	
	if (!manifest || !manifest_len || !type) {
		return rv;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		error("ERROR: Failed to decode image4 manifest\n");
		rv = -26;
		goto err;
	}
	
	if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
		info("Failed to get digest from image4 manifest\n");
		rv = 2;
		goto err;
	}
	
	if (mhash_len > 0x30) {
		error("ERROR: Too large hash size\n");
		rv = -28;
		goto err;
	}
	
	if (hash && hash_len) {
		uint8_t* _hash = malloc(mhash_len);
		if (!_hash) {
			error("ERROR: malloc failed\n");
			rv = -28;
			goto err;
		}
		memcpy(_hash, mhash, mhash_len);
		*hash = _hash;
		*hash_len = mhash_len;
	}
	
	rv = 0;
	
err:
	if (mhash) free(mhash);
	return rv;
}

#endif
