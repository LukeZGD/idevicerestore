/*
 * restore.c
 * Functions for handling idevices in restore mode
 *
 * Copyright (c) 2010-2013 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012-2015 Nikias Bassen. All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libimobiledevice/restore.h>
#include <zip.h>
#include <libirecovery.h>

#include "idevicerestore.h"
#include "asr.h"
#include "fdr.h"
#include "fls.h"
#include "mbn.h"
#include "tss.h"
#include "ipsw.h"
#include "restore.h"
#include "common.h"

#define CREATE_PARTITION_MAP          11
#define CREATE_FILESYSTEM             12
#define RESTORE_IMAGE                 13
#define VERIFY_RESTORE                14
#define CHECK_FILESYSTEMS             15
#define MOUNT_FILESYSTEMS             16
#define FIXUP_VAR                     17
#define FLASH_FIRMWARE                18
#define UPDATE_BASEBAND               19
#define SET_BOOT_STAGE                20
#define REBOOT_DEVICE                 21
#define SHUTDOWN_DEVICE               22
#define TURN_ON_ACCESSORY_POWER       23
#define CLEAR_BOOTARGS                24
#define MODIFY_BOOTARGS               25
#define INSTALL_ROOT                  26
#define INSTALL_KERNELCACHE           27
#define WAIT_FOR_NAND                 28
#define UNMOUNT_FILESYSTEMS           29
#define SET_DATETIME                  30
#define EXEC_IBOOT                    31
#define FINALIZE_NAND_EPOCH_UPDATE    32
#define CHECK_INAPPR_BOOT_PARTITIONS  33
#define CREATE_FACTORY_RESTORE_MARKER 34
#define LOAD_FIRMWARE                 35
#define CHECK_BATTERY_VOLTAGE         38
#define WAIT_BATTERY_CHARGE           39
#define CLOSE_MODEM_TICKETS           40
#define MIGRATE_DATA                  41
#define WIPE_STORAGE_DEVICE           42
#define SEND_APPLE_LOGO               43
#define CHECK_LOGS                    44
#define CLEAR_NVRAM                   46
#define UPDATE_GAS_GAUGE              47
#define PREPARE_BASEBAND_UPDATE       48
#define BOOT_BASEBAND                 49
#define CREATE_SYSTEM_KEYBAG          50
#define UPDATE_IR_MCU_FIRMWARE        51
#define RESIZE_SYSTEM_PARTITION       52
#define PAIR_STOCKHOLM                54
#define UPDATE_STOCKHOLM              55
#define UPDATE_SWDHID                 56
#define UPDATE_S3E_FIRMWARE           58
#define UPDATE_SE_FIRMWARE            59

static int restore_finished = 0;

static int restore_device_connected = 0;

int restore_client_new(struct idevicerestore_client_t* client) {
	struct restore_client_t* restore = (struct restore_client_t*) malloc(sizeof(struct restore_client_t));
	if (restore == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}

	if (restore_open_with_timeout(client) < 0) {
		restore_client_free(client);
		return -1;
	}

	client->restore = restore;
	return 0;
}

void restore_client_free(struct idevicerestore_client_t* client) {
	if (client && client->restore) {
		if(client->restore->client) {
			restored_client_free(client->restore->client);
			client->restore->client = NULL;
		}
		if(client->restore->device) {
			idevice_free(client->restore->device);
			client->restore->device = NULL;
		}
		if(client->restore->bbtss) {
			plist_free(client->restore->bbtss);
			client->restore->bbtss = NULL;
		}
		free(client->restore);
		client->restore = NULL;
	}
}

static int restore_idevice_new(struct idevicerestore_client_t* client, idevice_t* device)
{
	int num_devices = 0;
	char **devices = NULL;
	idevice_get_device_list(&devices, &num_devices);
	if (num_devices == 0) {
		return -1;
	}
	*device = NULL;
	idevice_t dev = NULL;
	idevice_error_t device_error;
	restored_client_t restore = NULL;
	int j;
	for (j = 0; j < num_devices; j++) {
		if (restore != NULL) {
			restored_client_free(restore);
			restore = NULL;
		}
		if (dev != NULL) {
			idevice_free(dev);
			dev = NULL;
		}
		device_error = idevice_new(&dev, devices[j]);
		if (device_error != IDEVICE_E_SUCCESS) {
			error("ERROR: %s: can't open device with UDID %s", __func__, devices[j]);
			continue;
		}

		if (restored_client_new(dev, &restore, "idevicerestore") != RESTORE_E_SUCCESS) {
			error("ERROR: %s: can't connect to restored on device with UDID %s", __func__, devices[j]);
			continue;

		}
		char* type = NULL;
		uint64_t version = 0;
		if (restored_query_type(restore, &type, &version) != RESTORE_E_SUCCESS) {
			continue;
		}
		if (strcmp(type, "com.apple.mobile.restored") != 0) {
			free(type);
			continue;
		}
		free(type);

		if (client->ecid != 0) {
			plist_t node = NULL;
			plist_t hwinfo = NULL;
			uint64_t this_cpid = (uint64_t)-1;
			uint64_t this_bdid = (uint64_t)-1;
			uint64_t this_ecid = (uint64_t)-1;

			if (restored_query_value(restore, "HardwareInfo", &hwinfo) != RESTORE_E_SUCCESS) {
				if (client->version && (client->version[0] == '1' || client->version[0] == '2')) {
					/*
						This info isn't available pre-iOS 3, so whatever
						Just don't restore multiple pre-iOS 3 devices at once ;)
					*/
					goto found_device;
				}
				continue;
			}

			node = plist_dict_get_item(hwinfo, "ChipID");
			if (node && plist_get_node_type(node) == PLIST_UINT) {
				plist_get_uint_val(node, &this_cpid);
			}

			node = plist_dict_get_item(hwinfo, "BoardID");
			if (node && plist_get_node_type(node) == PLIST_UINT) {
				plist_get_uint_val(node, &this_bdid);
			}

			node = plist_dict_get_item(hwinfo, "UniqueChipID");
			if (node && plist_get_node_type(node) == PLIST_UINT) {
				plist_get_uint_val(node, &this_ecid);
			}

			if (hwinfo) {
				plist_free(hwinfo);
			}

			if (this_ecid != client->ecid) {
				if (!client->version || (client->version[0] != '1' && client->version[0] != '2')) continue;
				/*
					UniqueChipID isn't available pre-iOS 3, so whatever
					Just don't restore multiple pre-iOS 3 devices at once ;)

					On iOS 2.1 0x8720 we do get CPID and BDID, so let's at least verify that
				*/
				if (this_cpid != -1 && this_cpid != client->device->chip_id) continue;
				if (this_bdid != -1 && this_bdid != client->device->board_id) continue;
			}
		}
	found_device:
		if (restore) {
			restored_client_free(restore);
			restore = NULL;
		}
		client->udid = strdup(devices[j]);
		*device = dev;
		break;
	}
	idevice_device_list_free(devices);

	return 0;
}

int restore_check_mode(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;

	restore_idevice_new(client, &device);
	if (!device) {
		return -1;
	}
	idevice_free(device);

	return 0;
}

const char* restore_check_hardware_model(struct idevicerestore_client_t* client) {
	char* model = NULL;
	plist_t node = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;
	irecv_device_t irecv_device = NULL;

	restore_idevice_new(client, &device);
	if (!device) {
		return NULL;
	}

	restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_free(device);
		return NULL;
	}

	if (restored_query_type(restore, NULL, NULL) != RESTORE_E_SUCCESS) {
		restored_client_free(restore);
		idevice_free(device);
		return NULL;
	}

	if (client->srnm == NULL) {
		if (restored_get_value(restore, "SerialNumber", &node) == RESTORE_E_SUCCESS) {
			plist_get_string_val(node, &client->srnm);
			info("INFO: device serial number is %s\n", client->srnm);
			plist_free(node);
			node = NULL;
		}
	}

	restore_error = restored_get_value(restore, "HardwareModel", &node);
	restored_client_free(restore);
	idevice_free(device);
	if (restore_error != RESTORE_E_SUCCESS || !node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to get HardwareModel from restored\n");
		plist_free(node);
		return NULL;
	}

	plist_get_string_val(node, &model);
	irecv_devices_get_device_by_hardware_model(model, &irecv_device);
	free(model);
	if (irecv_device && irecv_device->product_type) {
		return irecv_device->hardware_model;
	}

	return NULL;
}

void restore_device_callback(const idevice_event_t* event, void* userdata) {
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) userdata;
	if (event->event == IDEVICE_DEVICE_ADD) {
		restore_device_connected = 1;
		client->udid = strdup(event->udid);
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		restore_device_connected = 0;
		client->flags |= FLAG_QUIT;
	}
}

int restore_reboot(struct idevicerestore_client_t* client) {
	if(client->restore == NULL) {
		if (restore_open_with_timeout(client) < 0) {
			error("ERROR: Unable to open device in restore mode\n");
			return -1;
		}
	}

	info("Rebooting restore mode device...\n");
	restored_reboot(client->restore->client);

	restored_client_free(client->restore->client);

	// FIXME: wait for device disconnect here
	sleep(10);

	return 0;
}

static int restore_is_current_device(struct idevicerestore_client_t* client, const char* udid)
{
	if (!client) {
		return 0;
	}
	if (!client->ecid) {
		if (client->device && client->device->chip_id == 0x8900){
			/*
				iOS 1 restored doesn't tell us the device ECID, nor do we actually know it
			*/
			debug("%s: Skipping ECID check for 0x8900 device %s\n", __func__, udid);
			return 1;
		}else{
			error("ERROR: %s: no ECID given in client data\n", __func__);
			return 0;
		}
	}

	idevice_t device = NULL;
	idevice_error_t device_error;
	restored_client_t restored = NULL;
	restored_error_t restore_error;
	char *type = NULL;
	uint64_t version = 0;

	device_error = idevice_new(&device, udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: %s: can't open device with UDID %s", __func__, udid);
		return 0;
	}

	if (client->version && (client->version[0] == '1' || client->version[0] == '2')){
		sleep(10);
	}
	restore_error = restored_client_new(device, &restored, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: %s: can't connect to restored\n", __func__);
		idevice_free(device);
		return 0;
	}
	restore_error = restored_query_type(restored, &type, &version);
	if ((restore_error == RESTORE_E_SUCCESS) && type && (strcmp(type, "com.apple.mobile.restored") == 0)) {
		debug("%s: Connected to %s, version %d\n", __func__, type, (int)version);
	} else {
		info("%s: device %s is not in restore mode\n", __func__, udid);
		restored_client_free(restored);
		idevice_free(device);
		return 0;
	}

	plist_t hwinfo = NULL;
	restore_error = restored_query_value(restored, "HardwareInfo", &hwinfo);
	if ((restore_error != RESTORE_E_SUCCESS) || !hwinfo) {
		error("ERROR: %s: Unable to get HardwareInfo from restored\n", __func__);
		restored_client_free(restored);
		idevice_free(device);
		plist_free(hwinfo);
		if (client->version && (client->version[0] == '1' || client->version[0] == '2')) {
			/*
				This info isn't available pre-iOS 3, so whatever
				Just don't restore multiple pre-iOS 3 devices at once ;)
			*/
			debug("%s: pre-iOS 3 restore detected, continuing restore without ecid check!", __func__);
			return 1;
		}
		return 0;
	}
	restored_client_free(restored);
	idevice_free(device);

	uint64_t this_cpid = (uint64_t)-1;
	uint64_t this_bdid = (uint64_t)-1;
	uint64_t this_ecid = (uint64_t)-1;
	plist_t node = NULL;

	node = plist_dict_get_item(hwinfo, "ChipID");
	if (node && plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &this_cpid);
	}

	node = plist_dict_get_item(hwinfo, "BoardID");
	if (node && plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &this_bdid);
	}

	node = plist_dict_get_item(hwinfo, "UniqueChipID");
	if (node && plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &this_ecid);
	}

	plist_free(hwinfo); hwinfo = NULL;

	if (this_ecid == -1) {
		error("ERROR: %s: Unable to get ECID from restored\n", __func__);
		if (!client->version || (client->version[0] != '1' && client->version[0] != '2')) return 0;
		/*
			UniqueChipID isn't available pre-iOS 3, so whatever
			Just don't restore multiple pre-iOS 3 devices at once ;)

			On iOS 2.1 0x8720 we do get CPID and BDID, so let's at least verify that
		*/
		if (this_cpid != -1 && this_cpid != client->device->chip_id)  return 0;
		if (this_bdid != -1 && this_bdid != client->device->board_id)  return 0;
		debug("%s: pre-iOS 3 restore detected, continuing restore without ecid check!", __func__);
		return 1;
	}

	return (this_ecid == client->ecid);
}

static void restore_device_event_cb(const idevice_event_t *event, void *user_data)
{
	if (event->event == IDEVICE_DEVICE_ADD) {
		struct idevicerestore_client_t* client = (struct idevicerestore_client_t*)user_data;
		if (!restore_device_connected && restore_is_current_device(client, event->udid)) {
			restore_device_connected = 1;
			client->udid = strdup(event->udid);
		}
	}
}

int restore_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 180;
	char *type = NULL;
	uint64_t version = 0;
	idevice_t device = NULL;
	restored_client_t restored = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	// no context exists so bail
	if(client == NULL) {
		return -1;
	}

	if (client->ecid == 0 && (!client->device || client->device->chip_id != 0x8900)) {
		error("ERROR: no ECID in client data!\n");
		return -1;
	}

	// create our restore client if it doesn't yet exist
	if (client->restore == NULL) {
		client->restore = (struct restore_client_t*) malloc(sizeof(struct restore_client_t));
		if(client->restore == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
		memset(client->restore, '\0', sizeof(struct restore_client_t));
	}

	restore_device_connected = 0;

	info("Waiting for device...\n");
	idevice_event_subscribe(restore_device_event_cb, client);
	i = 0;
	while (i++ < attempts) {
		debug("Attempt %d to connect to restore mode device...\n", i);
		if (restore_device_connected) {
			info("Device %s is now connected in restore mode...\n", client->udid);
			break;
		}
		sleep(1);
	}
	idevice_event_unsubscribe();

	if (!restore_device_connected) {
		error("ERROR: Unable to connect to device in restore mode\n");
		return (i == attempts ? -2:-1);
	}

	info("Connecting now...\n");
	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(device, &restored, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_free(device);
		return -1;
	}

	restore_error = restored_query_type(restored, &type, &version);
	if ((restore_error == RESTORE_E_SUCCESS) && type && (strcmp(type, "com.apple.mobile.restored") == 0)) {
		client->restore->protocol_version = version;
		info("Connected to %s, version %d\n", type, (int)version);
	} else {
		error("ERROR: Unable to connect to restored, error=%d\n", restore_error);
		restored_client_free(restored);
		idevice_free(device);
		return -1;
	}

	client->restore->device = device;
	client->restore->client = restored;
	return 0;
}

const char* restore_progress_string(unsigned int operation)
{
	switch (operation) {
	case CREATE_PARTITION_MAP:
		return "Creating partition map";
	case CREATE_FILESYSTEM:
		return "Creating filesystem";
	case RESTORE_IMAGE:
		return "Restoring image";
	case VERIFY_RESTORE:
		return "Verifying restore";
	case CHECK_FILESYSTEMS:
		return "Checking filesystems";
	case MOUNT_FILESYSTEMS:
		return "Mounting filesystems";
	case FIXUP_VAR:
		return "Fixing up /var";
	case FLASH_FIRMWARE:
		return "Flashing firmware";
	case UPDATE_BASEBAND:
		return "Updating baseband";
	case SET_BOOT_STAGE:
		return "Setting boot stage";
	case REBOOT_DEVICE:
		return "Rebooting device";
	case SHUTDOWN_DEVICE:
		return "Shutdown device";
	case TURN_ON_ACCESSORY_POWER:
		return "Turning on accessory power";
	case CLEAR_BOOTARGS:
		return "Clearing persistent boot-args";
	case MODIFY_BOOTARGS:
		return "Modifying persistent boot-args";
	case INSTALL_ROOT:
		return "Installing root";
	case INSTALL_KERNELCACHE:
		return "Installing kernelcache";
	case WAIT_FOR_NAND:
		return "Waiting for NAND";
	case UNMOUNT_FILESYSTEMS:
		return "Unmounting filesystems";
	case SET_DATETIME:
		return "Setting date and time on device";
	case EXEC_IBOOT:
		return "Executing iBEC to bootstrap update";
	case FINALIZE_NAND_EPOCH_UPDATE:
		return "Finalizing NAND epoch update";
	case CHECK_INAPPR_BOOT_PARTITIONS:
		return "Checking for inappropriate bootable partitions";
	case CREATE_FACTORY_RESTORE_MARKER:
		return "Creating factory restore marker";
	case LOAD_FIRMWARE:
		return "Loading firmware data to flash";
	case CHECK_BATTERY_VOLTAGE:
		return "Checking battery voltage";
	case WAIT_BATTERY_CHARGE:
		return "Waiting for battery to charge";
	case CLOSE_MODEM_TICKETS:
		return "Closing modem tickets";
	case MIGRATE_DATA:
		return "Migrating data";
	case WIPE_STORAGE_DEVICE:
		return "Wiping storage device";
	case SEND_APPLE_LOGO:
		return "Sending Apple logo to device";
	case CHECK_LOGS:
		return "Checking for uncollected logs";
	case CLEAR_NVRAM:
		return "Clearing NVRAM";
	case UPDATE_GAS_GAUGE:
		return "Updating gas gauge software";
	case PREPARE_BASEBAND_UPDATE:
		return "Preparing for baseband update";
	case BOOT_BASEBAND:
		return "Booting the baseband";
	case CREATE_SYSTEM_KEYBAG:
		return "Creating system key bag";
	case UPDATE_IR_MCU_FIRMWARE:
		return "Updating IR MCU firmware";
	case RESIZE_SYSTEM_PARTITION:
		return "Resizing system partition";
	case PAIR_STOCKHOLM:
		return "Pairing Stockholm";
	case UPDATE_STOCKHOLM:
		return "Updating Stockholm";
	case UPDATE_SWDHID:
		return "Updating SWDHID";
	case UPDATE_S3E_FIRMWARE:
		return "Updating S3E Firmware";
	case UPDATE_SE_FIRMWARE:
		return "Updating SE Firmware";
	default:
		return "Unknown operation";
	}
}

static int lastop = 0;

int restore_handle_previous_restore_log_msg(restored_client_t client, plist_t msg) {
	plist_t node = NULL;
	char* restorelog = NULL;

	node = plist_dict_get_item(msg, "PreviousRestoreLog");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		debug("Failed to parse restore log from PreviousRestoreLog plist\n");
		return -1;
	}
	plist_get_string_val(node, &restorelog);

	info("Previous Restore Log Received:\n%s\n", restorelog);
	free(restorelog);

	return 0;
}

int restore_handle_progress_msg(struct idevicerestore_client_t* client, plist_t msg) {
	plist_t node = NULL;
	uint64_t progress = 0;
	uint64_t operation = 0;

	node = plist_dict_get_item(msg, "Operation");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		debug("Failed to parse operation from ProgressMsg plist\n");
		return -1;
	}
	plist_get_uint_val(node, &operation);

	node = plist_dict_get_item(msg, "Progress");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		debug("Failed to parse progress from ProgressMsg plist \n");
		return -1;
	}
	plist_get_uint_val(node, &progress);

	/* for restore protocol version < 14 all operation codes > 35 are 1 less so we add one */
	int adapted_operation = (int)operation;
	if (client && client->restore && client->restore->protocol_version < 14) {
		if (adapted_operation > 35) {
			adapted_operation++;
		}
	}

	if ((progress > 0) && (progress <= 100)) {
		if ((int)operation != lastop) {
			info("%s (%d)\n", restore_progress_string(adapted_operation), (int)operation);
		}
		switch (adapted_operation) {
		case VERIFY_RESTORE:
			idevicerestore_progress(client, RESTORE_STEP_VERIFY_FS, progress / 100.0);
			break;
		case FLASH_FIRMWARE:
			idevicerestore_progress(client, RESTORE_STEP_FLASH_FW, progress / 100.0);
			break;
		case UPDATE_BASEBAND:
		case UPDATE_IR_MCU_FIRMWARE:
			idevicerestore_progress(client, RESTORE_STEP_FLASH_BB, progress / 100.0);
			break;
		default:
			debug("Unhandled progress operation %d (%d)\n", adapted_operation, (int)operation);
			break;
		}
	} else {
		info("%s (%d)\n", restore_progress_string(adapted_operation), (int)operation);
	}
	lastop = (int)operation;

	return 0;
}

int restore_handle_status_msg(restored_client_t client, plist_t msg) {
	int result = 0;
	uint64_t value = 0;
	char* log = NULL;
	info("Got status message\n");

	// read status code
	plist_t node = plist_dict_get_item(msg, "Status");
	plist_get_uint_val(node, &value);

	switch(value) {
		case 0:
			info("Status: Restore Finished\n");
			restore_finished = 1;
			break;
		case 0xFFFFFFFFFFFFFFFFLL:
			info("Status: Verification Error\n");
			break;
		case 6:
			info("Status: Disk Failure\n");
			break;
		case 14:
			info("Status: Fail\n");
			break;
		case 27:
			info("Status: Failed to mount filesystems.\n");
			break;
		case 51:
			info("Status: Failed to load SEP Firmware.\n");
			break;
		case 53:
			info("Status: Failed to recover FDR data.\n");
			break;
		case 1015:
			info("Status: X-Gold Baseband Update Failed. Defective Unit?\n");
			break;
		default:
			info("Unhandled status message (" FMT_qu ")\n", (long long unsigned int)value);
			debug_plist(msg);
			break;
	}

	// read error code
	node = plist_dict_get_item(msg, "AMRError");
	if (node && plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &value);
		result = -value;
		if (result > 0) {
			result = -result;
		}
	}

	// check if log is available
	node = plist_dict_get_item(msg, "Log");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &log);
		info("Log is available:\n%s\n", log);
		free(log);
		log = NULL;
	}

	return result;
}

int restore_handle_bb_update_status_msg(restored_client_t client, plist_t msg)
{
	int result = -1;
	plist_t node = plist_dict_get_item(msg, "Accepted");
	uint8_t accepted = 0;
	plist_get_bool_val(node, &accepted);

	if (!accepted) {
		error("ERROR: device didn't accept BasebandData\n");
		return result;
	}

	uint8_t done = 0;
	node = plist_access_path(msg, 2, "Output", "done");
	if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
		plist_get_bool_val(node, &done);
	}

	if (done) {
		info("Updating Baseband completed.\n");
		plist_t provisioning = plist_access_path(msg, 2, "Output", "provisioning");
		if (provisioning && plist_get_node_type(provisioning) == PLIST_DICT) {
			char* sval = NULL;
			node = plist_dict_get_item(provisioning, "IMEI");
			if (node && plist_get_node_type(node) == PLIST_STRING) {
				plist_get_string_val(node, &sval);
				info("Provisioning:\n");
				info("IMEI:%s\n", sval);
				free(sval);
				sval = NULL;
			}
		}
	} else {
		info("Updating Baseband in progress...\n");
	}
	result = 0;

	return result;
}

static void restore_asr_progress_cb(double progress, void* userdata)
{
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*)userdata;
	if (client) {
		idevicerestore_progress(client, RESTORE_STEP_UPLOAD_FS, progress);
	}
}

int restore_send_filesystem(struct idevicerestore_client_t* client, idevice_t device, const char* filesystem) {
	asr_client_t asr = NULL;

	info("About to send filesystem...\n");

	if (asr_open_with_timeout(device, &asr) < 0) {
		error("ERROR: Unable to connect to ASR\n");
		return -1;
	}
	info("Connected to ASR\n");

	asr_set_progress_callback(asr, restore_asr_progress_cb, (void*)client);

	// this step sends requested chunks of data from various offsets to asr so
	// it can validate the filesystem before installing it
	info("Validating the filesystem\n");
	if (asr_perform_validation(asr, filesystem) < 0) {
		error("ERROR: ASR was unable to validate the filesystem\n");
		asr_free(asr);
		return -1;
	}
	info("Filesystem validated\n");

	// once the target filesystem has been validated, ASR then requests the
	// entire filesystem to be sent.
	info("Sending filesystem now...\n");
	if (asr_send_payload(asr, filesystem) < 0) {
		error("ERROR: Unable to send payload to ASR\n");
		asr_free(asr);
		return -1;
	}
	info("Done sending filesystem\n");

	asr_free(asr);
	return 0;
}

int restore_send_root_ticket(restored_client_t restore, struct idevicerestore_client_t* client)
{
	restored_error_t restore_error;
	plist_t dict;
	unsigned char* data = NULL;
	unsigned int len = 0;

	info("About to send RootTicket...\n");

	if (!client->tss && !(client->flags & FLAG_CUSTOM)) {
		error("ERROR: Cannot send RootTicket without TSS\n");
		return -1;
	}

	if (client->image4supported) {
		if (tss_response_get_ap_img4_ticket(client->tss, &data, &len) < 0) {
			error("ERROR: Unable to get ApImg4Ticket from TSS\n");
			return -1;
		}
	} else {
		if (!(client->flags & FLAG_CUSTOM) && (tss_response_get_ap_ticket(client->tss, &data, &len) < 0)) {
			error("ERROR: Unable to get ticket from TSS\n");
			return -1;
		}
	}

	dict = plist_new_dict();
	if (data && (len > 0)) {
		plist_dict_set_item(dict, "RootTicketData", plist_new_data((char*)data, len));
	} else {
		info("NOTE: not sending RootTicketData (no data present)\n");
	}

	info("Sending RootTicket now...\n");
	restore_error = restored_send(restore, dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send RootTicket (%d)\n", restore_error);
		plist_free(dict);
		return -1;
	}

	info("Done sending RootTicket\n");
	plist_free(dict);
	free(data);
	return 0;
}

int restore_send_kernelcache(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity) {
	unsigned int size = 0;
	unsigned char* data = NULL;
	char* path = NULL;
	plist_t blob = NULL;
	plist_t dict = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	info("About to send KernelCache...\n");

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, "KernelCache", &path) < 0) {
			debug("NOTE: No path for component KernelCache in TSS, will fetch from build_identity\n");
		}
	}
	if (!path) {
		if (build_identity_get_component_path(build_identity, "KernelCache", &path) < 0) {
			error("ERROR: Unable to find kernelcache path\n");
			return -1;
		}
	}

	const char* component = "KernelCache";
	unsigned char* component_data = NULL;
	unsigned int component_size = 0;
	int ret = extract_component(client->ipsw, path, &component_data, &component_size);
	free(path);
	path = NULL;
	if (ret < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		return -1;
	}

	ret = personalize_component(component, component_data, component_size, client->tss, &data, &size);
	free(component_data);
	component_data = NULL;
	if (ret < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		return -1;
	}

	dict = plist_new_dict();
	blob = plist_new_data((char*)data, size);
	plist_dict_set_item(dict, "KernelCacheFile", blob);
	free(data);

	info("Sending KernelCache now...\n");
	restore_error = restored_send(restore, dict);
	plist_free(dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		return -1;
	}

	info("Done sending KernelCache\n");
	return 0;
}

int restore_send_nor(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity) {
	char* llb_path = NULL;
	char* llb_filename = NULL;
	char* sep_path = NULL;
	char* restore_sep_path = NULL;
	char firmware_path[256];
	char manifest_file[256];
	unsigned int manifest_size = 0;
	unsigned char* manifest_data = NULL;
	char firmware_filename[256];
	unsigned int llb_size = 0;
	unsigned char* llb_data = NULL;
	plist_t dict = NULL;
	char* filename = NULL;
	unsigned int nor_size = 0;
	unsigned char* nor_data = NULL;
	plist_t norimage_array = NULL;
	plist_t firmware_files = NULL;
	uint32_t i;

	info("About to send NORData...\n");

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, "LLB", &llb_path) < 0) {
			debug("NOTE: Could not get LLB path from TSS data, will fetch from build identity\n");
		}
	}
	if (llb_path == NULL) {
		if (build_identity_get_component_path(build_identity, "LLB", &llb_path) < 0) {
			error("ERROR: Unable to get component path for LLB\n");
			return -1;
		}
	}

	llb_filename = strstr(llb_path, "LLB");
	if (llb_filename == NULL) {
		error("ERROR: Unable to extract firmware path from LLB filename\n");
		free(llb_path);
		return -1;
	}

	memset(firmware_path, '\0', sizeof(firmware_path));
	memcpy(firmware_path, llb_path, (llb_filename - 1) - llb_path);
	info("Found firmware path %s\n", firmware_path);

	memset(manifest_file, '\0', sizeof(manifest_file));
	snprintf(manifest_file, sizeof(manifest_file), "%s/manifest", firmware_path);

	firmware_files = plist_new_array();
	ipsw_extract_to_memory(client->ipsw, manifest_file, &manifest_data, &manifest_size);
	if (manifest_data && manifest_size > 0) {
		info("Getting firmware manifest from %s\n", manifest_file);
		char *manifest_p = (char*)manifest_data;
		while ((filename = strsep(&manifest_p, "\r\n")) != NULL) {
			if (*filename == '\0') continue;
			memset(firmware_filename, '\0', sizeof(firmware_filename));
			snprintf(firmware_filename, sizeof(firmware_filename), "%s/%s", firmware_path, filename);
			plist_array_append_item(firmware_files, plist_new_string(firmware_filename));
		}
		free(manifest_data);
	} else {
		info("Getting firmware manifest from build identity\n");
		plist_dict_iter iter = NULL;
		plist_t build_id_manifest = plist_dict_get_item(build_identity, "Manifest");
		if (build_id_manifest) {
			plist_dict_new_iter(build_id_manifest, &iter);
		}
		if (iter) {
			char *component;
			plist_t manifest_entry;
			do {
				component = NULL;
				manifest_entry = NULL;
				plist_dict_next_item(build_id_manifest, iter, &component, &manifest_entry);
				if (component && manifest_entry && plist_get_node_type(manifest_entry) == PLIST_DICT) {
					uint8_t is_fw = 0;
					plist_t is_fw_node = plist_access_path(manifest_entry, 2, "Info", "IsFirmwarePayload");
					if (is_fw_node && plist_get_node_type(is_fw_node) == PLIST_BOOLEAN) {
						plist_get_bool_val(is_fw_node, &is_fw);
					}
					if (is_fw) {
						plist_t comp_path = plist_access_path(manifest_entry, 2, "Info", "Path");
						if (comp_path) {
							plist_array_append_item(firmware_files, plist_copy(comp_path));
						}
					}
				}
			} while (manifest_entry);
			free(iter);
		}
	}

	if (plist_array_get_size(firmware_files) == 0) {
		error("ERROR: Unable to get list of firmware files.\n");
		return -1;
	}

	const char* component = "LLB";
	unsigned char* component_data = NULL;
	unsigned int component_size = 0;
	int ret = extract_component(client->ipsw, llb_path, &component_data, &component_size);
	free(llb_path);
	if (ret < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		return -1;
	}

	ret = personalize_component(component, component_data, component_size, client->tss, &llb_data, &llb_size);
	free(component_data);
	component_data = NULL;
	component_size = 0;
	if (ret < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		return -1;
	}

	dict = plist_new_dict();
	plist_dict_set_item(dict, "LlbImageData", plist_new_data((char*)llb_data, (uint64_t) llb_size));
	free(llb_data);

	if (client->restore->protocol_version == 7){
		//iOS 1.0 support
		plist_dict_set_item(dict,"Operation", plist_new_string("UpdateNOR"));
	}

	norimage_array = plist_new_array();

	for (i = 0; i < plist_array_get_size(firmware_files); i++) {
		plist_t pcomp = plist_array_get_item(firmware_files, i);
		char *comppath = NULL;

		plist_get_string_val(pcomp, &comppath);
		if (!comppath) continue;

		filename = strrchr(comppath, '/');
		if (!filename) {
			free(comppath);
			continue;
		}
		filename++;

		component = get_component_name(filename);
		if (!strcmp(component, "LLB") || !strcmp(component, "RestoreSEP")) {
			// skip LLB, it's already passed in LlbImageData
			// skip RestoreSEP, it's passed in RestoreSEPImageData
			free(comppath);
			continue;
		}

		component_data = NULL;
		unsigned int component_size = 0;

		if (extract_component(client->ipsw, comppath, &component_data, &component_size) < 0) {
			free(comppath);
			plist_free(firmware_files);
			error("ERROR: Unable to extract component: %s\n", component);
			return -1;
		}
		free(comppath);

		if (personalize_component(component, component_data, component_size, client->tss, &nor_data, &nor_size) < 0) {
			free(component_data);
			plist_free(firmware_files);
			error("ERROR: Unable to get personalized component: %s\n", component);
			return -1;
		}
		free(component_data);
		component_data = NULL;
		component_size = 0;

		/* make sure iBoot is the first entry in the array */
		if (!strncmp("iBoot", filename, 4)) {
			plist_array_insert_item(norimage_array, plist_new_data((char*)nor_data, (uint64_t)nor_size), 0);
		} else {
			plist_array_append_item(norimage_array, plist_new_data((char*)nor_data, (uint64_t)nor_size));
		}

		free(nor_data);
		nor_data = NULL;
		nor_size = 0;
	}
	plist_free(firmware_files);
	plist_dict_set_item(dict, "NorImageData", norimage_array);

	unsigned char* personalized_data = NULL;
	unsigned int personalized_size = 0;

	if (!build_identity_has_component(build_identity, "RestoreSEP") &&
	    build_identity_get_component_path(build_identity, "RestoreSEP", &restore_sep_path) == 0) {
		component = "RestoreSEP";
        if (!client->sepfwdatasize) ret = extract_component(client->ipsw, restore_sep_path, &component_data, &component_size);
        else{
            component_data = malloc(component_size = (unsigned int)client->sepfwdatasize);
            memcpy(component_data, client->sepfwdata, component_size);
        }
        
        free(restore_sep_path);
        if (ret < 0) {
			error("ERROR: Unable to extract component: %s\n", component);
			return -1;
		}

        ret = personalize_component(component, component_data, component_size, (client->septss) ? client->septss : client->tss, &personalized_data, &personalized_size);
        free(component_data);
		component_data = NULL;
		component_size = 0;
		if (ret < 0) {
			error("ERROR: Unable to get personalized component: %s\n", component);
			return -1;
		}

		plist_dict_set_item(dict, "RestoreSEPImageData", plist_new_data((char*)personalized_data, (uint64_t) personalized_size));
		free(personalized_data);
		personalized_data = NULL;
		personalized_size = 0;
	}

	if (!build_identity_has_component(build_identity, "SEP") &&
	    build_identity_get_component_path(build_identity, "SEP", &sep_path) == 0) {
		component = "SEP";
        if (!client->sepfwdatasize) ret = extract_component(client->ipsw, sep_path, &component_data, &component_size);
        else{
            component_data = malloc(component_size = (unsigned int)client->sepfwdatasize);
            memcpy(component_data, client->sepfwdata, component_size);
        }
        free(sep_path);
		if (ret < 0) {
			error("ERROR: Unable to extract component: %s\n", component);
			return -1;
		}

		ret = personalize_component(component, component_data, component_size, (client->septss) ? client->septss : client->tss, &personalized_data, &personalized_size);
        free(component_data);
		component_data = NULL;
		component_size = 0;
		if (ret < 0) {
			error("ERROR: Unable to get personalized component: %s\n", component);
			return -1;
		}

		plist_dict_set_item(dict, "SEPImageData", plist_new_data((char*)personalized_data, (uint64_t) personalized_size));
		free(personalized_data);
		personalized_data = NULL;
		personalized_size = 0;
	}

	if (idevicerestore_debug)
		debug_plist(dict);

	info("Sending NORData now...\n");
	if (restored_send(restore, dict) != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send NORImageData data\n");
		plist_free(dict);
		return -1;
	}

	info("Done sending NORData\n");
	plist_free(dict);
	return 0;
}

static const char* restore_get_bbfw_fn_for_element(const char* elem)
{
	struct bbfw_fn_elem_t {
		const char* element;
		const char* fn;
	};

	struct bbfw_fn_elem_t bbfw_fn_elem[] = {
		// ICE3 firmware files
		{ "RamPSI", "psi_ram.fls" },
		{ "FlashPSI", "psi_flash.fls" },
		// Trek firmware files
		{ "eDBL", "dbl.mbn" },
		{ "RestoreDBL", "restoredbl.mbn" },
		// Phoenix/Mav4 firmware files
		{ "DBL", "dbl.mbn" },
		{ "ENANDPRG", "ENPRG.mbn" },	
		// Mav5 firmware files
		{ "RestoreSBL1", "restoresbl1.mbn" },
		{ "SBL1", "sbl1.mbn" },
		// ICE16 firmware files
		{ "RestorePSI", "restorepsi.bin", },
		{ "PSI", "psi_ram.bin" },
		{ NULL, NULL }
	};

	int i;
	for (i = 0; bbfw_fn_elem[i].element != NULL; i++) {
		if (strcmp(bbfw_fn_elem[i].element, elem) == 0) {
			return bbfw_fn_elem[i].fn;
		}
	}
	return NULL;
}

static int restore_sign_bbfw(const char* bbfwtmp, plist_t bbtss, const unsigned char* bb_nonce)
{
	int res = -1;

	// check for BBTicket in result
	plist_t bbticket = plist_dict_get_item(bbtss, "BBTicket");
	if (!bbticket || plist_get_node_type(bbticket) != PLIST_DATA) {
		error("ERROR: Could not find BBTicket in Baseband TSS response\n");
		return -1;
	}

	plist_t bbfw_dict = plist_dict_get_item(bbtss, "BasebandFirmware");
	if (!bbfw_dict || plist_get_node_type(bbfw_dict) != PLIST_DICT) {
		error("ERROR: Could not find BasebandFirmware Dictionary node in Baseband TSS response\n");
		return -1;
	}

	unsigned char* buffer = NULL;
	unsigned char* blob = NULL;
	unsigned char* fdata = NULL;
	off_t fsize = 0;
	uint64_t blob_size = 0;
	int zerr = 0;
	int zindex = -1;
	struct zip_stat zstat;
	struct zip_file* zfile = NULL;
	struct zip* za = NULL;
	struct zip_source* zs = NULL;
	mbn_file* mbn = NULL;
	fls_file* fls = NULL;

	za = zip_open(bbfwtmp, 0, &zerr);
	if (!za) {
		error("ERROR: Could not open ZIP archive '%s': %d\n", bbfwtmp, zerr);
		goto leave;
	}

	plist_dict_iter iter = NULL;
	plist_dict_new_iter(bbfw_dict, &iter);
	if (!iter) {
		error("ERROR: Could not create dict iter for BasebandFirmware Dictionary\n");
		return -1;
	}

	int is_fls = 0;
	int signed_file_idxs[16];
	int signed_file_count = 0;
	char* key = NULL;
	plist_t node = NULL;
	while (1) {
		plist_dict_next_item(bbfw_dict, iter, &key, &node);
		if (key == NULL)
			break;
		if (node && (strcmp(key + (strlen(key) - 5), "-Blob") == 0) && (plist_get_node_type(node) == PLIST_DATA)) {
			char *ptr = strchr(key, '-');
			*ptr = '\0';
			const char* signfn = restore_get_bbfw_fn_for_element(key);
			if (!signfn) {
				error("ERROR: can't match element name '%s' to baseband firmware file name.\n", key);
				goto leave;
			}
			char* ext = strrchr(signfn, '.');
			if (!strcmp(ext, ".fls")) {
				is_fls = 1;
			}

			zindex = zip_name_locate(za, signfn, 0);
			if (zindex < 0) {
				error("ERROR: can't locate '%s' in '%s'\n", signfn, bbfwtmp);
				goto leave;
			}

			zip_stat_init(&zstat);
			if (zip_stat_index(za, zindex, 0, &zstat) != 0) {
				error("ERROR: zip_stat_index failed for index %d\n", zindex);
				goto leave;
			}

			zfile = zip_fopen_index(za, zindex, 0);
			if (zfile == NULL) {
				error("ERROR: zip_fopen_index failed for index %d\n", zindex);
				goto leave;
			}

			buffer = (unsigned char*) malloc(zstat.size + 1);
			if (buffer == NULL) {
				error("ERROR: Out of memory\n");
				goto leave;
			}

			if (zip_fread(zfile, buffer, zstat.size) != zstat.size) {
				error("ERROR: zip_fread: failed\n");
				goto leave;
			}
			buffer[zstat.size] = '\0';

			zip_fclose(zfile);
			zfile = NULL;

			if (is_fls) {
				fls = fls_parse(buffer, zstat.size);
				if (!fls) {
					error("ERROR: could not parse fls file\n");
					goto leave;
				}
			} else {
				mbn = mbn_parse(buffer, zstat.size);
				if (!mbn) {
					error("ERROR: could not parse mbn file\n");
					goto leave;
				}
			}
			free(buffer);
			buffer = NULL;

			blob = NULL;
			blob_size = 0;
			plist_get_data_val(node, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get %s-Blob data\n", key);
				goto leave;
			}

			if (is_fls) {
				if (fls_update_sig_blob(fls, blob, (unsigned int)blob_size) != 0) {
					error("ERROR: could not sign %s\n", signfn);
					goto leave;
				}
			} else {
				if (mbn_update_sig_blob(mbn, blob, (unsigned int)blob_size) != 0) {
					error("ERROR: could not sign %s\n", signfn);
					goto leave;
				}
			}
			free(blob);
			blob = NULL;

			fsize = (is_fls ? fls->size : mbn->size);
			fdata = (unsigned char*)malloc(fsize);
			if (fdata == NULL)  {
				error("ERROR: out of memory\n");
				goto leave;
			}
			if (is_fls) {
				memcpy(fdata, fls->data, fsize);
				fls_free(fls);
				fls = NULL;
			} else {
				memcpy(fdata, mbn->data, fsize);
				mbn_free(mbn);
				mbn = NULL;
			}

			zs = zip_source_buffer(za, fdata, fsize, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				free(fdata);
				goto leave;
			}

			if (zip_replace(za, zindex, zs) == -1) {
				error("ERROR: could not update signed '%s' in archive\n", signfn);
				goto leave;
			}

			if (is_fls && !bb_nonce) {
				if (strcmp(key, "RamPSI") == 0) {
					signed_file_idxs[signed_file_count++] = zindex;
				}
			} else {
				signed_file_idxs[signed_file_count++] = zindex;
			}
		}
		free(key);
	}
	free(iter);

	// remove everything but required files
	int i, j, keep, numf = zip_get_num_files(za);
	for (i = 0; i < numf; i++) {
		keep = 0;
		// check for signed file index
		for (j = 0; j < signed_file_count; j++) {
			if (i == signed_file_idxs[j]) {
				keep = 1;
				break;
			}
		}
		// check for anything but .mbn and .fls if bb_nonce is set
		if (bb_nonce && !keep) {
			const char* fn = zip_get_name(za, i, 0);
			if (fn) {
				char* ext = strrchr(fn, '.');
				if (ext && (!strcmp(ext, ".fls") || !strcmp(ext, ".mbn") || !strcmp(ext, ".elf") || !strcmp(ext, ".bin"))) {
					keep = 1;
				}
			}
		}
		if (!keep) {
			zip_delete(za, i);
		}
	}

	if (bb_nonce) {
		if (is_fls) {
			// add BBTicket to file ebl.fls
			zindex = zip_name_locate(za, "ebl.fls", 0);
			if (zindex < 0) {
				error("ERROR: can't locate 'ebl.fls' in '%s'\n", bbfwtmp);
				goto leave;
			}

			zip_stat_init(&zstat);
			if (zip_stat_index(za, zindex, 0, &zstat) != 0) {
				error("ERROR: zip_stat_index failed for index %d\n", zindex);
				goto leave;
			}

			zfile = zip_fopen_index(za, zindex, 0);
			if (zfile == NULL) {
				error("ERROR: zip_fopen_index failed for index %d\n", zindex);
				goto leave;
			}

			buffer = (unsigned char*) malloc(zstat.size + 1);
			if (buffer == NULL) {
				error("ERROR: Out of memory\n");
				goto leave;
			}

			if (zip_fread(zfile, buffer, zstat.size) != zstat.size) {
				error("ERROR: zip_fread: failed\n");
				goto leave;
			}
			buffer[zstat.size] = '\0';

			zip_fclose(zfile);
			zfile = NULL;

			fls = fls_parse(buffer, zstat.size);
			free(buffer);
			buffer = NULL;
			if (!fls) {
				error("ERROR: could not parse fls file\n");
				goto leave;
			}

			blob = NULL;
			blob_size = 0;
			plist_get_data_val(bbticket, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get BBTicket data\n");
				goto leave;
			}

			if (fls_insert_ticket(fls, blob, (unsigned int)blob_size) != 0) {
				error("ERROR: could not insert BBTicket to ebl.fls\n");
				goto leave;
			}
			free(blob);
			blob = NULL;

			fsize = fls->size;
			fdata = (unsigned char*)malloc(fsize);
			if (!fdata) {
				error("ERROR: out of memory\n");
				goto leave;
			}
			memcpy(fdata, fls->data, fsize);
			fls_free(fls);
			fls = NULL;

			zs = zip_source_buffer(za, fdata, fsize, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				free(fdata);
				goto leave;
			}

			if (zip_replace(za, zindex, zs) == -1) {
				error("ERROR: could not update archive with ticketed ebl.fls\n");
				goto leave;
			}
		} else {
			// add BBTicket as bbticket.der
			blob = NULL;
			blob_size = 0;
			plist_get_data_val(bbticket, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get BBTicket data\n");
				goto leave;
			}

			zs = zip_source_buffer(za, blob, blob_size, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				goto leave;
			}
			blob = NULL;

			if (zip_add(za, "bbticket.der", zs) == -1) {
				error("ERROR: could not add bbticket.der to archive\n");
				goto leave;
			}
		}
	}

	// this will write out the modified zip
	if (zip_close(za) == -1) {
		error("ERROR: could not close and write modified archive: %s\n", zip_strerror(za));
		res = -1;
	} else {
		res = 0;
	}
	za = NULL;
	zs = NULL;

leave:
	if (zfile) {
		zip_fclose(zfile);
	}
	if (zs) {
		zip_source_free(zs);
	}
	if (za) {
		zip_unchange_all(za);
		zip_close(za);
	}
	mbn_free(mbn);
	fls_free(fls);
	free(buffer);
	free(blob);

	return res;
}

int restore_send_baseband_data(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity, plist_t message)
{
	int res = -1;
	uint64_t bb_cert_id = 0;
	unsigned char* bb_snum = NULL;
	uint64_t bb_snum_size = 0;
	unsigned char* bb_nonce = NULL;
	uint64_t bb_nonce_size = 0;
	uint64_t bb_chip_id = 0;
	plist_t response = NULL;
	char* buffer = NULL;
	char* bbfwtmp = NULL;
    if (client->bbfwtmp) bbfwtmp = strdup(client->bbfwtmp);
	plist_t dict = NULL;

	info("About to send BasebandData...\n");

	// NOTE: this function is called 2 or 3 times!

	// setup request data
	plist_t arguments = plist_dict_get_item(message, "Arguments");
	if (arguments && plist_get_node_type(arguments) == PLIST_DICT) {
		plist_t bb_chip_id_node = plist_dict_get_item(arguments, "ChipID");
		if (bb_chip_id_node && plist_get_node_type(bb_chip_id_node) == PLIST_UINT) {
			plist_get_uint_val(bb_chip_id_node, &bb_chip_id);
		}
		plist_t bb_cert_id_node = plist_dict_get_item(arguments, "CertID");
		if (bb_cert_id_node && plist_get_node_type(bb_cert_id_node) == PLIST_UINT) {
			plist_get_uint_val(bb_cert_id_node, &bb_cert_id);
		}
		plist_t bb_snum_node = plist_dict_get_item(arguments, "ChipSerialNo");
		if (bb_snum_node && plist_get_node_type(bb_snum_node) == PLIST_DATA) {
			plist_get_data_val(bb_snum_node, (char**)&bb_snum, &bb_snum_size);
		}
		plist_t bb_nonce_node = plist_dict_get_item(arguments, "Nonce");
		if (bb_nonce_node && plist_get_node_type(bb_nonce_node) == PLIST_DATA) {
			plist_get_data_val(bb_nonce_node, (char**)&bb_nonce, &bb_nonce_size);
		}
	}

	if ((bb_nonce == NULL) || (client->restore->bbtss == NULL)) {
		/* populate parameters */
		plist_t parameters = plist_new_dict();
		plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
		if (bb_nonce) {
			plist_dict_set_item(parameters, "BbNonce", plist_new_data((const char*)bb_nonce, bb_nonce_size));
        }else{
            info("sending request without baseband nonce\n");
        }
		plist_dict_set_item(parameters, "BbChipID", plist_new_uint(bb_chip_id));
		plist_dict_set_item(parameters, "BbGoldCertId", plist_new_uint(bb_cert_id));
		plist_dict_set_item(parameters, "BbSNUM", plist_new_data((const char*)bb_snum, bb_snum_size));

		tss_parameters_add_from_manifest(parameters, build_identity);

		/* create baseband request */
		plist_t request = tss_request_new(NULL);
		if (request == NULL) {
			error("ERROR: Unable to create Baseband TSS request\n");
			plist_free(parameters);
			return -1;
		}

        tss_request_add_common_tags(request, parameters, NULL);
//        tss_request_add_ap_tags(request, parameters, NULL);
        
        
        //we don't want an apticket
        if (client->image4supported)
            plist_dict_set_item(request, "@ApImg4Ticket", plist_new_bool(0));
        else
            plist_dict_set_item(request, "@APTicket", plist_new_bool(0));
        
		/* add baseband parameters */
		tss_request_add_baseband_tags(request, parameters, NULL);

		plist_t node = plist_access_path(build_identity, 2, "Info", "FDRSupport");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			uint8_t b = 0;
			plist_get_bool_val(node, &b);
			if (b) {
				plist_dict_set_item(request, "ApProductionMode", plist_new_bool(1));
				plist_dict_set_item(request, "ApSecurityMode", plist_new_bool(1));
			}
		}
		if (idevicerestore_debug)
			debug_plist(request);

		info("Sending Baseband TSS request...\n");
		response = tss_request_send(request, client->tss_url);
		plist_free(request);
		plist_free(parameters);
		if (response == NULL) {
			error("ERROR: Unable to fetch Baseband TSS\n");
			return -1;
		}
		info("Received Baseband SHSH blobs\n");

		if (idevicerestore_debug)
			debug_plist(response);
	}

	// get baseband firmware file path from build identity
	plist_t bbfw_path = plist_access_path(build_identity, 4, "Manifest", "BasebandFirmware", "Info", "Path");
	if (!bbfw_path || plist_get_node_type(bbfw_path) != PLIST_STRING) {
		error("ERROR: Unable to get BasebandFirmware/Info/Path node\n");
		plist_free(response);
		return -1;
	}
	char* bbfwpath = NULL;
	plist_get_string_val(bbfw_path, &bbfwpath);	
	if (!bbfwpath) {
		error("ERROR: Unable to get baseband path\n");
		plist_free(response);
		return -1;
	}

    // extract baseband firmware to temp file
    bbfwtmp = tempnam(NULL, client->udid);
    if (!bbfwtmp) {
        error("WARNING: Could not generate temporary filename, using bbfw.tmp\n");
        bbfwtmp = strdup("bbfw.tmp");
    }
    if (!client->bbfwtmp) {
        if (ipsw_extract_to_file(client->ipsw, bbfwpath, bbfwtmp) != 0) {
            error("ERROR: Unable to extract baseband firmware from ipsw\n");
            plist_free(response);
            return -1;
        }
    }else{
        FILE *f1 = fopen(client->bbfwtmp,"r");
        FILE *f2 = fopen(bbfwtmp,"w");
        size_t s;
        fseek(f1, 0, SEEK_END);
        s = ftell(f1);
        fseek(f1, 0, SEEK_SET);
        
        char * buf = malloc(s);
        fread(buf, 1, s, f1);
        fwrite(buf, 1, s, f2);
        fclose(f1);
        fclose(f2);
    }

	if (bb_nonce && !client->restore->bbtss) {
		// keep the response for later requests
		client->restore->bbtss = response;
		response = NULL;
	}

	res = restore_sign_bbfw(bbfwtmp, (client->restore->bbtss) ? client->restore->bbtss : response, bb_nonce);
	if (res != 0) {
		goto leave;
	}

	res = -1;
	
	size_t sz = 0;
	if (read_file(bbfwtmp, (void**)&buffer, &sz) < 0) {
		error("ERROR: could not read updated bbfw archive\n");
		goto leave;
	}

	// send file
	dict = plist_new_dict();
	plist_dict_set_item(dict, "BasebandData", plist_new_data(buffer, (uint64_t)sz));
	free(buffer);
	buffer = NULL;

	info("Sending BasebandData now...\n");
	if (restored_send(restore, dict) != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send BasebandData data\n");
		goto leave;
	}

	info("Done sending BasebandData\n");
	res = 0;

leave:
	plist_free(dict);
	free(buffer);
	if (bbfwtmp) {
		remove(bbfwtmp);
		free(bbfwtmp);
	}
	plist_free(response);

	return res;
}

int restore_send_fdr_trust_data(restored_client_t restore, idevice_t device)
{
	restored_error_t restore_error;
	plist_t dict;

	info("About to send FDR Trust data...\n");

	// FIXME: What should we send here?
	/* Sending an empty dict makes it continue with FDR
	 * and this is what iTunes seems to be doing too */
	dict = plist_new_dict();

	info("Sending FDR Trust data now...\n");
	restore_error = restored_send(restore, dict);
	plist_free(dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: During sending FDR Trust data (%d)\n", restore_error);
		return -1;
	}

	info("Done sending FDR Trust Data\n");

	return 0;
}

int restore_send_fud_data(restored_client_t restore, struct idevicerestore_client_t *client, plist_t build_identity)
{
	restored_error_t restore_error;
	plist_t dict;
	plist_t fud_dict;
	plist_t build_id_manifest;
	plist_dict_iter iter = NULL;

	info("About to send FUD data...\n");

	fud_dict = plist_new_dict();

	build_id_manifest = plist_dict_get_item(build_identity, "Manifest");
	if (build_id_manifest) {
		plist_dict_new_iter(build_id_manifest, &iter);
	}
	if (iter) {
		char *component;
		plist_t manifest_entry;
		do {
			component = NULL;
			manifest_entry = NULL;
			plist_dict_next_item(build_id_manifest, iter, &component, &manifest_entry);
			if (component && manifest_entry && plist_get_node_type(manifest_entry) == PLIST_DICT) {
				uint8_t is_fud = 0;
				plist_t is_fud_node = plist_access_path(manifest_entry, 2, "Info", "IsFUDFirmware");
				if (is_fud_node && plist_get_node_type(is_fud_node) == PLIST_BOOLEAN) {
					plist_get_bool_val(is_fud_node, &is_fud);
				}
				if (is_fud) {
					char *path = NULL;
					unsigned char* data = NULL;
					unsigned int size = 0;
					unsigned char* component_data = NULL;
					unsigned int component_size = 0;
					int ret = -1;

					info("Found FUD component '%s'\n", component);

					build_identity_get_component_path(build_identity, component, &path);
					if (path) {
						ret = extract_component(client->ipsw, path, &component_data, &component_size);
					}
					free(path);
					path = NULL;
					if (ret < 0) {
						error("ERROR: Unable to extract component: %s\n", component);
					}

					ret = personalize_component(component, component_data, component_size, client->tss, &data, &size);
					free(component_data);
					component_data = NULL;
					if (ret < 0) {
						error("ERROR: Unable to get personalized component: %s\n", component);
						return -1;
					}

					plist_dict_set_item(fud_dict, component, plist_new_data((const char*)data, size));
					free(data);
				}
				free(component);
			}
		} while (manifest_entry);
		free(iter);
	}

	dict = plist_new_dict();
	plist_dict_set_item(dict, "FUDImageData", fud_dict);

	info("Sending FUD data now...\n");
	restore_error = restored_send(restore, dict);
	plist_free(dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: During sending FUD data (%d)\n", restore_error);
		return -1;
	}

	info("Done sending FUD data\n");

	return 0;
}

plist_t restore_get_se_firmware_data(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity, plist_t p_info)
{
	const char *comp_name = "SE,Firmware";
	char *comp_path = NULL;
	unsigned char* component_data = NULL;
	unsigned int component_size = 0;
	plist_t fwdict = NULL;
	plist_t parameters = NULL;
	plist_t request = NULL;
	plist_t response = NULL;
	int ret;

	if (build_identity_get_component_path(build_identity, comp_name, &comp_path) < 0) {
		error("ERROR: Unable get path for '%s' component\n", comp_name);
		return NULL;
	}

	ret = extract_component(client->ipsw, comp_path, &component_data, &component_size);
	free(comp_path);
	comp_path = NULL;
	if (ret < 0) {
		error("ERROR: Unable to extract '%s' component\n", comp_name);
		return NULL;
	}

	/* create SE request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		error("ERROR: Unable to create SE TSS request\n");
		free(component_data);
		return NULL;
	}

	parameters = plist_new_dict();

	/* add manifest for current build_identity to parameters */
	tss_parameters_add_from_manifest(parameters, build_identity);

	/* add SE,* tags from info dictionary to parameters */
	plist_dict_merge(&parameters, p_info);

	/* add required tags for SE TSS request */
	tss_request_add_se_tags(request, parameters, NULL);

	plist_free(parameters);

	info("Sending SE TSS request...\n");
	response = tss_request_send(request, client->tss_url);
	plist_free(request);
	if (response == NULL) {
		error("ERROR: Unable to fetch SE ticket\n");
		free(component_data);
		return NULL;
	}

	if (plist_dict_get_item(response, "SE,Ticket")) {
		info("Received SE ticket\n");
	} else {
		error("ERROR: No 'SE,Ticket' in TSS response, this might not work\n");
	}

	plist_dict_set_item(response, "FirmwareData", plist_new_data((char*)component_data, (uint64_t) component_size));
	free(component_data);
	component_data = NULL;
	component_size = 0;

	return response;
}

int restore_send_firmware_updater_data(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity, plist_t message)
{
	plist_t arguments;
	plist_t p_type, p_updater_name, p_loop_count, p_info;
	plist_t loop_count_dict = NULL;
	char *s_type = NULL;
	plist_t dict = NULL;
	plist_t fwdict = NULL;
	char *s_updater_name = NULL;
	int restore_error;

	if (idevicerestore_debug) {
		debug("DEBUG: Got FirmwareUpdaterData request:\n", __func__);
		debug_plist(message);
	}

	arguments = plist_dict_get_item(message, "Arguments");
	if (!arguments || plist_get_node_type(arguments) != PLIST_DICT) {
		error("ERROR: %s: Arguments missing or has invalid type!\n", __func__);
		goto error_out;
	}

	p_type = plist_dict_get_item(arguments, "MessageArgType");
	if (!p_type || (plist_get_node_type(p_type) != PLIST_STRING)) {
		error("ERROR: %s: MessageArgType missing or has invalid type!\n", __func__);
		goto error_out;
	}

	p_updater_name = plist_dict_get_item(arguments, "MessageArgUpdaterName");
	if (!p_updater_name || (plist_get_node_type(p_updater_name) != PLIST_STRING)) {
		error("ERROR: %s: MessageArgUpdaterName missing or has invalid type!\n", __func__);
		goto error_out;
	}

	p_loop_count = plist_dict_get_item(arguments, "MessageArgUpdaterLoopCount");
	if (p_loop_count) {
		loop_count_dict = plist_new_dict();
		plist_dict_set_item(loop_count_dict, "LoopCount", plist_copy(p_loop_count));
	}

	plist_get_string_val(p_type, &s_type);
	if (!s_type || strcmp(s_type, "FirmwareResponseData")) {
		error("ERROR: %s: MessageArgType has unexpected value '%s'\n", __func__, s_type);
		goto error_out;
	}
	free(s_type);
	s_type = NULL;

	p_info = plist_dict_get_item(arguments, "MessageArgInfo");
	if (!p_info || (plist_get_node_type(p_info) != PLIST_DICT)) {
		error("ERROR: %s: MessageArgInfo missing or has invalid type!\n", __func__);
		goto error_out;
	}

	plist_get_string_val(p_updater_name, &s_updater_name);

	if (strcmp(s_updater_name, "SE")) {
		error("ERROR: %s: Got unknown updater name '%s'.", __func__, s_updater_name);
		goto error_out;
	}
	free(s_updater_name);
	s_updater_name = NULL;

	fwdict = restore_get_se_firmware_data(restore, client, build_identity, p_info);
	if (fwdict == NULL) {
		error("ERROR: %s: Couldn't get SE firmware data\n", __func__);
		goto error_out;
	}

	dict = plist_new_dict();
	plist_dict_set_item(dict, "FirmwareResponseData", fwdict);

	info("Sending FirmwareResponse data now...\n");
	restore_error = restored_send(restore, dict);
	plist_free(dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Couldn't send FirmwareResponse data (%d)\n", restore_error);
		goto error_out;
	}

	info("Done sending FirmwareUpdater data\n");

	return 0;

error_out:
	free(s_type);
	free(s_updater_name);
	plist_free(loop_count_dict);
	return -1;
}

int restore_handle_data_request_msg(struct idevicerestore_client_t* client, idevice_t device, restored_client_t restore, plist_t message, plist_t build_identity, const char* filesystem)
{
	char* type = NULL;
	plist_t node = NULL;

	// checks and see what kind of data restored is requests and pass
	// the request to its own handler
	node = plist_dict_get_item(message, "DataType");
	if (node && PLIST_STRING == plist_get_node_type(node)) {
		plist_get_string_val(node, &type);

		// this request is sent when restored is ready to receive the filesystem
		if (!strcmp(type, "SystemImageData")) {
			if(restore_send_filesystem(client, device, filesystem) < 0) {
				error("ERROR: Unable to send filesystem\n");
				return -2;
			}
		}

		// send RootTicket (== APTicket from the TSS request)
		else if (!strcmp(type, "RootTicket")) {
			if (restore_send_root_ticket(restore, client) < 0) {
				error("ERROR: Unable to send RootTicket\n");
				return -1;
			}
		}
		// send KernelCache
		else if (!strcmp(type, "KernelCache")) {
			if(restore_send_kernelcache(restore, client, build_identity) < 0) {
				error("ERROR: Unable to send kernelcache\n");
				return -1;
			}
		}

		else if (!strcmp(type, "NORData")) {
			if((client->flags & FLAG_EXCLUDE) == 0) {
				if(restore_send_nor(restore, client, build_identity) < 0) {
					error("ERROR: Unable to send NOR data\n");
					return -1;
				}
			} else {
				info("Not sending NORData... Quitting...\n");
				client->flags |= FLAG_QUIT;
			}
		}

		else if (!strcmp(type, "BasebandData")) {
            if(restore_send_baseband_data(restore, client, (client->basebandBuildIdentity) ? client->basebandBuildIdentity : build_identity, message) < 0) {
				error("ERROR: Unable to send baseband data\n");
				return -1;
			}
		}

		else if (!strcmp(type, "FDRTrustData")) {
			if(restore_send_fdr_trust_data(restore, device) < 0) {
				error("ERROR: Unable to send FDR Trust data\n");
				return -1;
			}
		}

		else if (!strcmp(type, "FUDData")) {
			if(restore_send_fud_data(restore, client, build_identity) < 0) {
				error("ERROR: Unable to send FUD data\n");
				return -1;
			}
		}

		else if (!strcmp(type, "FirmwareUpdaterData")) {
			if(restore_send_firmware_updater_data(restore, client, build_identity, message) < 0) {
				error("ERROR: Unable to send FirmwareUpdater data\n");
				return -1;
			}
		}

		else {
			// Unknown DataType!!
			error("Unknown data request '%s' received\n", type);
			if (idevicerestore_debug)
				debug_plist(message);
		}
	}
	return 0;
}

static int restore_process_v7_protocol(struct idevicerestore_client_t* client, plist_t message, uint64_t *v7_restore_stage,  plist_t build_identity){
	int err = 0;
	restored_client_t restore = NULL;
	idevice_t device = NULL;
    plist_t p_response = NULL;
    plist_t p_status = NULL;

	restore = client->restore->client;
	device = client->restore->device;

    int64_t complete_status = -1;

#define MAKE_STAGE(stage, num) (stage | (((uint64_t)num) << 55))
#define GET_STAGE(v) ((v) & ((1LLU<<56)-1))
#define GET_NUM(v) ((int)((v) >> 55))

    p_response = plist_dict_get_item(message, "Response");
    if (!p_response || plist_get_node_type(p_response) != PLIST_STRING) {
        debug("Unknown message received:\n");
        //if (idevicerestore_debug)
            debug_plist(message);
        return 0;
    }

    if (!plist_string_val_compare(p_response, "Acknowledged")) {
        if (*v7_restore_stage == RESTORE_IMAGE){
            if(restore_send_filesystem(client, device, build_identity) < 0) {
                error("ERROR: Unable to send filesystem\n");
                err = -2;
                client->flags |= FLAG_QUIT;
            }else{
                info("Verifying filesystem...\n");
            }
        }
        info("%s (%d) ...",restore_progress_string(GET_STAGE(*v7_restore_stage)),GET_NUM(*v7_restore_stage));
        fflush(stdout);
        return 0;
    }else if (!plist_string_val_compare(p_response, "Complete")) {

        p_status = plist_dict_get_item(message, "Status");
        if (!p_status || plist_get_node_type(p_status) != PLIST_INT) {
            error("Failed to get Complete status from message:\n");
            //if (idevicerestore_debug)
                debug_plist(message);
        }
        plist_get_int_val(p_status, &complete_status);
        info(" done. (status %lld)\n",complete_status);
    }else{
        error("Unexpected Response Type: %s\n",plist_get_string_ptr(p_response,NULL));
    }

    if (complete_status != 0){
        return -7;
    }

    plist_t dict = plist_new_dict();
    switch (*v7_restore_stage) {
    case MAKE_STAGE(WAIT_FOR_NAND,0):
        *v7_restore_stage = MAKE_STAGE(CREATE_PARTITION_MAP,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Partition"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(CREATE_PARTITION_MAP,0):
        *v7_restore_stage = MAKE_STAGE(CREATE_FILESYSTEM,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Erase"));
        plist_dict_set_item(dict,"VolumeName", plist_new_string("System"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s1"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(CREATE_FILESYSTEM,0):
        *v7_restore_stage = MAKE_STAGE(CREATE_FILESYSTEM,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Erase"));
        plist_dict_set_item(dict,"VolumeName", plist_new_string("Data"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s2"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(CREATE_FILESYSTEM,1):
        *v7_restore_stage = MAKE_STAGE(RESTORE_IMAGE,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Restore"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s1"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(RESTORE_IMAGE,0):
        *v7_restore_stage = MAKE_STAGE(CHECK_FILESYSTEMS,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("FilesystemCheck"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s1"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(CHECK_FILESYSTEMS,0):
        *v7_restore_stage = MAKE_STAGE(MOUNT_FILESYSTEMS,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Mount"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s1"));
        plist_dict_set_item(dict,"MountPoint", plist_new_string("/mnt1"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(MOUNT_FILESYSTEMS,0):
        *v7_restore_stage = MAKE_STAGE(CHECK_FILESYSTEMS,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("FilesystemCheck"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s2"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(CHECK_FILESYSTEMS,1):
        *v7_restore_stage = MAKE_STAGE(MOUNT_FILESYSTEMS,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Mount"));
        plist_dict_set_item(dict,"DeviceName", plist_new_string("/dev/disk0s2"));
        plist_dict_set_item(dict,"MountPoint", plist_new_string("/mnt2"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(MOUNT_FILESYSTEMS,1):
        *v7_restore_stage = MAKE_STAGE(FIXUP_VAR,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Ditto"));
        plist_dict_set_item(dict,"SourcePath", plist_new_string("/mnt1/private/var"));
        plist_dict_set_item(dict,"DestinationPath", plist_new_string("/mnt2"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(FIXUP_VAR,0):
        *v7_restore_stage = MAKE_STAGE(FIXUP_VAR,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("MakeDirectory"));
        plist_dict_set_item(dict,"Mode", plist_new_string("750"));
        plist_dict_set_item(dict,"Path", plist_new_string("/mnt2/root/Media"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(FIXUP_VAR,1):
        *v7_restore_stage = MAKE_STAGE(FIXUP_VAR,2);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("RemovePath"));
        plist_dict_set_item(dict,"Path", plist_new_string("/mnt1/private/var"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(FIXUP_VAR,2):
        *v7_restore_stage = MAKE_STAGE(FIXUP_VAR,3);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("MakeDirectory"));
        plist_dict_set_item(dict,"Mode", plist_new_string("755"));
        plist_dict_set_item(dict,"Path", plist_new_string("/mnt1/private/var"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(FIXUP_VAR,3):
        *v7_restore_stage = MAKE_STAGE(UNMOUNT_FILESYSTEMS,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Unmount"));
        plist_dict_set_item(dict,"MountPoint", plist_new_string("/mnt1"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(UNMOUNT_FILESYSTEMS,0):
        *v7_restore_stage = MAKE_STAGE(UNMOUNT_FILESYSTEMS,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("Unmount"));
        plist_dict_set_item(dict,"MountPoint", plist_new_string("/mnt2"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(UNMOUNT_FILESYSTEMS,1):
        *v7_restore_stage = MAKE_STAGE(FLASH_FIRMWARE,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        err = restore_send_nor(restore, client, build_identity);
        break;

    case MAKE_STAGE(FLASH_FIRMWARE,0):
        *v7_restore_stage = MAKE_STAGE(UPDATE_BASEBAND,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("UpdateBaseBand"));
        plist_dict_set_item(dict,"UpdateBasebandBootloader", plist_new_bool(1));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(UPDATE_BASEBAND,0):
        *v7_restore_stage = MAKE_STAGE(SET_BOOT_STAGE,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("SetBootStage"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(SET_BOOT_STAGE,0):
        *v7_restore_stage = MAKE_STAGE(MODIFY_BOOTARGS,0);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("SetNVRam"));
        plist_dict_set_item(dict,"NVRAMKey", plist_new_string("auto-boot"));
        plist_dict_set_item(dict,"NVRAMValue", plist_new_string("true"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(MODIFY_BOOTARGS,0):
        *v7_restore_stage = MAKE_STAGE(MODIFY_BOOTARGS,1);
        debug("Requesting Stage 0x%llx\n",*v7_restore_stage);
        plist_dict_set_item(dict,"Operation", plist_new_string("SetNVRam"));
        plist_dict_set_item(dict,"NVRAMKey", plist_new_string("bootdelay"));
        plist_dict_set_item(dict,"NVRAMValue", plist_new_string("0"));
        err = restored_send(restore, dict);
        break;

    case MAKE_STAGE(MODIFY_BOOTARGS,1):
        info("Done restoring\n");
        client->flags |= FLAG_QUIT;
        break;

    default:
        error("Restore at unexpected stage %lld (0x%llx)\n",*v7_restore_stage,*v7_restore_stage);
        err = -7;
        break;
    }
    if (dict){plist_free(dict); dict = NULL;}
    return err;
#undef MAKE_STAGE
#undef GET_STAGE
#undef GET_NUM
}

int restore_device(struct idevicerestore_client_t* client, plist_t build_identity, const char* filesystem) {
	int err = 0;
	char* type = NULL;
	plist_t node = NULL;
	plist_t message = NULL;
	plist_t hwinfo = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;
	thread_t fdr_thread = NULL;
	uint64_t v7_restore_stage = WAIT_FOR_NAND;

	restore_finished = 0;

	// open our connection to the device and verify we're in restore mode
	err = restore_open_with_timeout(client);
	if (err < 0) {
		error("ERROR: Unable to open device in restore mode\n");
		return (err == -2) ? -1: -2;
	}
	info("Device %s has successfully entered restore mode\n", client->udid);

	restore = client->restore->client;
	device = client->restore->device;

	restore_error = restored_query_value(restore, "HardwareInfo", &hwinfo);
	if (restore_error == RESTORE_E_SUCCESS) {
		uint64_t i = 0;
		uint8_t b = 0;
		info("Hardware Information:\n");

		node = plist_dict_get_item(hwinfo, "BoardID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("BoardID: %d\n", (int)i);
		}

		node = plist_dict_get_item(hwinfo, "ChipID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("ChipID: %d\n", (int)i);
		}

		node = plist_dict_get_item(hwinfo, "UniqueChipID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("UniqueChipID: " FMT_qu "\n", (long long unsigned int)i);
		}

		node = plist_dict_get_item(hwinfo, "ProductionMode");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			plist_get_bool_val(node, &b);
			info("ProductionMode: %s\n", (b==1) ? "true":"false");
		}
		plist_free(hwinfo);
	}

	restore_error = restored_query_value(restore, "SavedDebugInfo", &hwinfo);
    node = NULL;
	if (restore_error == RESTORE_E_SUCCESS) {
		char* sval = NULL;

		node = plist_dict_get_item(hwinfo, "PreviousExitStatus");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("Previous restore exit status: %s\n", sval);
			free(sval);
			sval = NULL;
		}

		node = plist_dict_get_item(hwinfo, "USBLog");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("USB log is available:\n%s\n", sval);
			free(sval);
			sval = NULL;
		}

		node = plist_dict_get_item(hwinfo, "PanicLog");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("Panic log is available:\n%s\n", sval);
			free(sval);
			sval = NULL;
		}
		plist_free(hwinfo);
	}

    if (client->flags & FLAG_PANICLOG) {
        if (!node) {
            info("No paniclog available\n");
        }
        restore_reboot(client);
        return 0;
    }
    
//	if (plist_dict_get_item(client->tss, "BBTicket")) {
//		client->restore->bbtss = plist_copy(client->tss);
//	}

	fdr_client_t fdr_control_channel = NULL;

	plist_t opts = plist_new_dict();
	// FIXME: required?
	//plist_dict_set_item(opts, "AuthInstallRestoreBehavior", plist_new_string("Erase"));
	plist_dict_set_item(opts, "AutoBootDelay", plist_new_uint(0));

	if (client->preflight_info) {
		plist_t node;
		plist_t bbus = plist_copy(client->preflight_info);	

		plist_dict_remove_item(bbus, "FusingStatus");
		plist_dict_remove_item(bbus, "PkHash");

		plist_dict_set_item(opts, "BBUpdaterState", bbus);

		node = plist_dict_get_item(client->preflight_info, "Nonce");
		if (node) {
			plist_dict_set_item(opts, "BasebandNonce", plist_copy(node));
		}
	}

	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "BootImageType", plist_new_string("UserOrInternal"));
	// FIXME: required?
	//plist_dict_set_item(opts, "BootImageFile", plist_new_string("018-7923-347.dmg"));
	plist_dict_set_item(opts, "CreateFilesystemPartitions", plist_new_bool(1));
	plist_dict_set_item(opts, "DFUFileType", plist_new_string("RELEASE"));
	plist_dict_set_item(opts, "DataImage", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "DeviceTreeFile", plist_new_string("DeviceTree.k48ap.img3"));
	plist_dict_set_item(opts, "FirmwareDirectory", plist_new_string("."));
	// FIXME: usable if false? (-x parameter)
	plist_dict_set_item(opts, "FlashNOR", plist_new_bool(1));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "KernelCacheFile", plist_new_string("kernelcache.release.k48"));
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "KernelCacheType", plist_new_string("Release"));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "NORImagePath", plist_new_string("."));
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "NORImageType", plist_new_string("production"));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "PersonalizedRestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	if (client->restore_boot_args) {
		plist_dict_set_item(opts, "RestoreBootArgs", plist_new_string(client->restore_boot_args));
	}
	plist_dict_set_item(opts, "RestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	plist_dict_set_item(opts, "RootToInstall", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "SourceRestoreBundlePath", plist_new_string("/tmp"));
	plist_dict_set_item(opts, "SystemImage", plist_new_bool(1));
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "SystemImageType", plist_new_string("User"));
	plist_t spp = plist_access_path(build_identity, 2, "Info", "SystemPartitionPadding");
	if (spp) {
		spp = plist_copy(spp);
	} else {
		spp = plist_new_dict();
		plist_dict_set_item(spp, "128", plist_new_uint(1280));
		plist_dict_set_item(spp, "16", plist_new_uint(160));
		plist_dict_set_item(spp, "32", plist_new_uint(320));
		plist_dict_set_item(spp, "64", plist_new_uint(640));
		plist_dict_set_item(spp, "8", plist_new_uint(80));
	}
	plist_dict_set_item(opts, "SystemPartitionPadding", spp);
	char* guid = generate_guid();
	if (guid) {
		plist_dict_set_item(opts, "UUID", plist_new_string(guid));
		free(guid);
	}
	// FIXME: does this have any effect actually?
	plist_dict_set_item(opts, "UpdateBaseband", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "UserLocale", plist_new_string("en_US"));

	/* this is mandatory on iOS 7+ to allow restore from normal mode */
	plist_dict_set_item(opts, "PersonalizedDuringPreflight", plist_new_bool(1));

	// start the restore process
	restore_error = restored_start_restore(restore, opts, client->restore->protocol_version);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start the restore process\n");
		plist_free(opts);
		restore_client_free(client);
		return -1;
	}
	plist_free(opts);
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 1.0);

	// this is the restore process loop, it reads each message in from
	// restored and passes that data on to it's specific handler
	while ((client->flags & FLAG_QUIT) == 0) {
		// finally, if any of these message handlers returned -1 then we encountered
		// an unrecoverable error, so we need to bail.
		if (err < 0) {
			error("ERROR: Unable to successfully restore device\n");
			client->flags |= FLAG_QUIT;
		}

		if (message) {plist_free(message);message = NULL;}
		restore_error = restored_receive(restore, &message);
		if (restore_error != RESTORE_E_SUCCESS) {
			debug("No data to read\n");
			continue;
		}

		if (client->restore->protocol_version == 7){
			//iOS 1.0X restores
            err = restore_process_v7_protocol(client, message, &v7_restore_stage, build_identity);

        }else{ //iOS 1.1 and everything newer
			// discover what kind of message has been received
			node = plist_dict_get_item(message, "MsgType");
			if (!node || plist_get_node_type(node) != PLIST_STRING) {
				debug("Unknown message received:\n");
				//if (idevicerestore_debug)
					debug_plist(message);
				plist_free(message);
				continue;
			}
			plist_get_string_val(node, &type);

			// data request messages are sent by restored whenever it requires
			// files sent to the server by the client. these data requests include
			// SystemImageData, RootTicket, KernelCache, NORData and BasebandData requests
			if (!strcmp(type, "DataRequestMsg")) {
				err = restore_handle_data_request_msg(client, device, restore, message, build_identity, filesystem);
			}

			// restore logs are available if a previous restore failed
			else if (!strcmp(type, "PreviousRestoreLogMsg")) {
				err = restore_handle_previous_restore_log_msg(restore, message);
			}

			// progress notification messages sent by the restored inform the client
			// of it's current operation and sometimes percent of progress is complete
			else if (!strcmp(type, "ProgressMsg")) {
				err = restore_handle_progress_msg(client, message);
			}

			// status messages usually indicate the current state of the restored
			// process or often to signal an error has been encountered
			else if (!strcmp(type, "StatusMsg")) {
				err = restore_handle_status_msg(restore, message);
				if (restore_finished) {
					client->flags |= FLAG_QUIT;
				}
			}

			// baseband update message
			else if (!strcmp(type, "BBUpdateStatusMsg")) {
				err = restore_handle_bb_update_status_msg(restore, message);
			}

			// there might be some other message types i'm not aware of, but I think
			// at least the "previous error logs" messages usually end up here
			else {
				debug("Unknown message type received\n");
				//if (idevicerestore_debug)
					debug_plist(message);
			}
		}
	}

	if (type) {free(type); type = NULL;}
	if (message) {plist_free(message);message = NULL;}

	if (fdr_control_channel) {
		fdr_disconnect(fdr_control_channel);
		if (fdr_thread) {
			thread_join(fdr_thread);
		}
		fdr_control_channel = NULL;
	}

	restore_client_free(client);
	return err;
}
