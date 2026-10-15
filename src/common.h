/*
 * common.h
 * Misc functions used in idevicerestore
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
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

#ifndef IDEVICERESTORE_COMMON_H
#define IDEVICERESTORE_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <unistd.h>

#include <plist/plist.h>
#include <libirecovery.h>
#include <libimobiledevice-glue/thread.h>

#include "idevicerestore.h"

#define _MODE_UNKNOWN         0
#define _MODE_WTF             1
#define _MODE_DFU             2
#define _MODE_RECOVERY        3
#define _MODE_RESTORE         4
#define _MODE_NORMAL          5
#define _MODE_PORTDFU         6
#define _MODE_PONGO           7

#define MODE_UNKNOWN  &idevicerestore_modes[_MODE_UNKNOWN]
#define MODE_WTF      &idevicerestore_modes[_MODE_WTF]
#define MODE_DFU      &idevicerestore_modes[_MODE_DFU]
#define MODE_RECOVERY &idevicerestore_modes[_MODE_RECOVERY]
#define MODE_RESTORE  &idevicerestore_modes[_MODE_RESTORE]
#define MODE_NORMAL   &idevicerestore_modes[_MODE_NORMAL]
#define MODE_PORTDFU  &idevicerestore_modes[_MODE_PORTDFU]
#define MODE_PONGO    &idevicerestore_modes[_MODE_PONGO]

#define FLAG_QUIT            1

#define CPFM_FLAG_SECURITY_MODE 1 << 0
#define CPFM_FLAG_PRODUCTION_MODE 1 << 1

#define IBOOT_FLAG_IMAGE4_AWARE  1 << 2
#define IBOOT_FLAG_EFFECTIVE_SECURITY_MODE 1 << 3
#define IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE 1 << 4

#define USER_AGENT_STRING "InetURL/1.0"

struct dfu_client_t;
struct normal_client_t;
struct restore_client_t;
struct recovery_client_t;
struct ipsw_archive;

typedef struct ipsw_archive* ipsw_archive_t;

struct idevicerestore_mode_t {
	int index;
	const char* string;
};

struct idevicerestore_entry_t {
	char* name;
	char* path;
	char* filename;
	char* blob_data;
	uint32_t blob_size;
	struct idevicerestore_entry* next;
	struct idevicerestore_entry* prev;
};

struct idevicerestore_client_t {
	uint64_t flags;
	int debug_level;
	plist_t tss;
	plist_t tss_localpolicy;
	plist_t tss_recoveryos_root_ticket;
	char* tss_url;
	plist_t version_data;
	uint64_t ecid;
	unsigned char* nonce;
	int nonce_size;
	int image4supported;
	plist_t build_manifest;
	plist_t firmware_preflight_info;
	plist_t preflight_info;
	plist_t parameters;
	char* udid;
	char* srnm;
	ipsw_archive_t ipsw;
	struct dfu_client_t* dfu;
	struct restore_client_t* restore;
	struct recovery_client_t* recovery;
	irecv_device_t device;
	struct idevicerestore_entry_t** entries;
	struct idevicerestore_mode_t* mode;
	char* version;
	char* build;
	char* device_version;
	char* device_build;
	int build_major;
	char* restore_boot_args;
	char* cache_dir;
	unsigned char* root_ticket;
	int root_ticket_len;
	idevicerestore_progress_cb_t progress_cb;
	void* progress_cb_data;
	irecv_device_event_context_t irecv_e_ctx;
	void* idevice_e_ctx;
	mutex_t device_event_mutex;
	cond_t device_event_cond;
	int ignore_device_add_events;
	plist_t macos_variant;
	plist_t recovery_variant;
	char* restore_variant;
	char* filesystem;
	int delete_fs;
	int async_err;
    
#ifdef HAVE_TURDUS_MERULA
	int disable_serial_output;
	int is_32bit_soc;
	uint16_t cpid;
	uint8_t bdid;
	plist_t local_shsh;
	int use_custom_ticket;
	
	int need_asr_patch;
	
	int get_shc_block;
	int get_pte_block;
	
	int sep_fwload_race;
	int sep_boot_tz0_race;
	
	char* cryptex1_nonce_seed;
	void* sepi_im4p; // 'sepi' im4p
	size_t sepi_im4p_len;
	void* rsep_img4; // signed 'rsep' img4
	size_t rsep_img4_len;
	void* img4_manifest;
	uint64_t img4_manifest_len;
	void* img4_manifest_hash;
	size_t img4_manifest_hash_len;
	void* sep_shellcode_block;
	size_t sep_shellcode_block_len;
	
	int use_specific_fwver_component;
	char* signed_variant;
	plist_t signed_manifest;
	plist_t signed_identity;
	
	uint8_t* bbfw;
	size_t bbfw_len;
	
	uint8_t* sefw;
	size_t sefw_len;
	
	uint8_t* rsepfw;
	size_t rsepfw_len;
	
	// ios 9 haxx
	uint8_t* alternative_ibss;
	size_t alternative_ibss_len;
	
	const char* alternative_hardware_model;
	plist_t alternative_bbfw_manifest;
	plist_t alternative_bbfw_identity;
	uint8_t* alternative_bbfw;
	size_t alternative_bbfw_len;
	
	// tethered
	uint8_t* t_LLB;
	size_t t_LLB_len;
	uint8_t* t_AppleLogo;
	size_t t_AppleLogo_len;
	uint8_t* t_BatteryCharging0;
	size_t t_BatteryCharging0_len;
	uint8_t* t_BatteryCharging1;
	size_t t_BatteryCharging1_len;
	uint8_t* t_BatteryFull;
	size_t t_BatteryFull_len;
	uint8_t* t_BatteryLow0;
	size_t t_BatteryLow0_len;
	uint8_t* t_BatteryLow1;
	size_t t_BatteryLow1_len;
	uint8_t* t_BatteryPlugin;
	size_t t_BatteryPlugin_len;
	uint8_t* t_RecoveryMode;
	size_t t_RecoveryMode_len;
	uint8_t* t_iBoot;
	size_t t_iBoot_len;
#endif
};

#ifdef HAVE_TURDUS_MERULA
typedef struct {
	uint32_t magic;         // 'bsep'
	uint32_t total_size;    // total block size
	uint32_t block_version; // block version
	uint32_t block_size;    // block size
	uint32_t undefined_0;
	uint32_t undefined_1;
	
	uint64_t undefined_2;
	uint16_t undefined_3;
	uint16_t type;          // payload type
	/* ... */
} sep_block_t;

#define BSEP_MAGIC (0x70657362)
#define BSEP_VERSION_1 (1uLL)
#define BSEP_TYPE_NONE (0)
#define BSEP_TYPE_SHC  (1uLL << 0)
#define BSEP_TYPE_PTE  (1uLL << 1)

#endif

extern struct idevicerestore_mode_t idevicerestore_modes[];

extern int idevicerestore_debug;

__attribute__((format(printf, 1, 2)))
void info(const char* format, ...);
__attribute__((format(printf, 1, 2)))
void error(const char* format, ...);
__attribute__((format(printf, 1, 2)))
void debug(const char* format, ...);

void debug_plist(plist_t plist);
void print_progress_bar(double progress);
int read_file(const char* filename, void** data, size_t* size);
int read_file_safe(const char* filename, void** data, size_t* size, size_t max_size);
int write_file(const char* filename, const void* data, size_t size);

char *generate_guid(void);

#ifdef WIN32
#include <windows.h>
#include <unistd.h>
#define __mkdir(path, mode) mkdir(path)
#ifndef sleep
#define sleep(x) Sleep(x*1000)
#endif
#define __usleep(x) Sleep(x/1000)
#else
#include <sys/stat.h>
#define __mkdir(path, mode) mkdir(path, mode)
#define __usleep(x) usleep(x)
#endif

#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif

int mkdir_with_parents(const char *dir, int mode);

char *get_temp_filename(const char *prefix);

void idevicerestore_progress(struct idevicerestore_client_t* client, int step, double progress);

#ifndef HAVE_STRSEP
char* strsep(char** strp, const char* delim);
#endif

#ifndef HAVE_REALPATH
char* realpath(const char *filename, char *resolved_name);
#endif

void get_user_input(char *buf, int maxlen, int secure);

const char* path_get_basename(const char* path);

#ifdef __cplusplus
}
#endif

#endif
