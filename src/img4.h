/*
 * img4.h
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

#ifndef IDEVICERESTORE_IMG4_H
#define IDEVICERESTORE_IMG4_H

#ifdef __cplusplus
extern "C" {
#endif

int img4_stitch_component(const char* component_name, const unsigned char* component_data, unsigned int component_size, plist_t parameters, plist_t tss_response, unsigned char** img4_data, unsigned int *img4_size);
int img4_create_local_manifest(plist_t request, plist_t build_identity, plist_t* manifest);

#ifdef HAVE_TURDUS_MERULA
#define IMG4_DIGEST_ERROR             (0)
#define IMG4_DIGEST_VALID_MANIFEST    (1 << 0)
#define IMG4_DIGEST_MATCHED_MANIFEST  (1 << 1)
#define IMG4_DIGEST_VALID_PAYLOAD     (1 << 2)
#define IMG4_DIGEST_MATCHED_PAYLOAD   (1 << 3)

void img4_override_payload_tag(const char* component_name, const unsigned char* component_data);
int get_img4_digest_from_manifest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname, const uint8_t* manifest, const size_t manifest_len, uint8_t** hash, size_t* hash_len);
int get_boot_nonce_hash_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint8_t** boot_nonce_hash, size_t *nonce_hash_length);
int validate_boot_nonce_hash(struct idevicerestore_client_t* client);
int validate_img4_digest(
						 struct idevicerestore_client_t* client,
						 plist_t build_identity,
						 const char *compname,
						 const uint8_t* payload,
						 const size_t payload_len,
						 const uint8_t* manifest,
						 const size_t manifest_len,
						 bool verify_manifest,
						 bool verify_payload,
						 uint32_t* result
						 );
int get_image4_manifest_hash(const uint8_t* manifest, const size_t manifest_len, uint32_t type, uint8_t** hash, size_t* hash_len);
int validate_ECID(struct idevicerestore_client_t* client);

#endif

#ifdef __cplusplus
}
#endif

#endif
