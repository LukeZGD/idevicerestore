/*
 * legacy.c
 * Functions for handling iPhone OS 1 recovery mode
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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "legacy.h"
#include "idevicerestore.h"
#include "ipsw.h"

struct legacy_usb {
	irecv_client_t handle;
	unsigned char types[256];
	unsigned short packets[256];
	unsigned int release;
};

int legacy_is_ios1(struct idevicerestore_client_t *client)
{
	return client && client->device && client->device->chip_id == 0x8900 &&
		client->version && client->version[0] == '1' && client->version[1] == '.';
}

int legacy_set_boot_args(struct idevicerestore_client_t *client)
{
	const char *source = client->restore_boot_args ? client->restore_boot_args :
		"rd=md0 nand-enable-reformat=1 -progress";
	char *args = malloc(strlen(source) + 16);
	if (!args) return -1;
	size_t size = 0;
	while (*source) {
		while (isspace((unsigned char)*source)) source++;
		const char *start = source;
		while (*source && !isspace((unsigned char)*source)) source++;
		size_t length = source - start;
		if (!length || (length >= 7 && !strncmp(start, "serial=", 7))) continue;
		if (size) args[size++] = ' ';
		memcpy(args + size, start, length);
		size += length;
	}
	if (size) args[size++] = ' ';
	memcpy(args + size, "serial=3", 9);
	free(client->restore_boot_args);
	client->restore_boot_args = args;
	return 0;
}

static unsigned int read16(const unsigned char *p)
{
	return p[0] | ((unsigned int)p[1] << 8);
}

static void write32(unsigned char *p, uint32_t n)
{
	for (unsigned int i = 0; i < 4; i++) p[i] = n >> (8 * i);
}

static irecv_device_t legacy_device(irecv_client_t handle, unsigned int *release)
{
	int mode = 0;
	unsigned char descriptor[18];
	if (irecv_get_mode(handle, &mode) != IRECV_E_SUCCESS || mode != IRECV_K_RECOVERY_MODE_1 ||
		irecv_usb_control_transfer(handle, 0x80, 6, 0x0100, 0, descriptor, sizeof(descriptor), 1000) != sizeof(descriptor) ||
		read16(descriptor + 8) != 0x05ac || read16(descriptor + 10) != 0x1280) {
		return NULL;
	}
	unsigned int model = read16(descriptor + 12) & 0xff00;
	if (release) *release = read16(descriptor + 12);
	irecv_device_t device = NULL;
	if (model == 0x1100 || model == 0x2100) {
		irecv_devices_get_device_by_product_type(model == 0x1100 ? "iPhone1,1" : "iPod1,1", &device);
	}
	return device;
}

irecv_device_t legacy_recovery_probe(struct idevicerestore_client_t *client)
{
	if (client->ecid || client->udid || (client->flags & FLAG_QUIT)) return NULL;
	irecv_client_t handle = NULL;
	if (irecv_open_with_ecid(&handle, 0) != IRECV_E_SUCCESS) return NULL;
	irecv_device_t device = legacy_device(handle, NULL);
	irecv_close(handle);
	if (device && client->device && strcmp(device->product_type, client->device->product_type)) return NULL;
	return device;
}

static int legacy_transfer(struct legacy_usb *usb, unsigned char endpoint, unsigned char *data, int size, int *transferred)
{
	*transferred = 0;
	if (usb->types[endpoint] == 3) {
		return irecv_usb_interrupt_transfer(usb->handle, endpoint, data, size, transferred, 10000);
	}
	return irecv_usb_bulk_transfer(usb->handle, endpoint, data, size, transferred, 10000);
}

static int legacy_request(struct legacy_usb *usb, unsigned int operation, uint32_t size, uint32_t address)
{
	unsigned char request[12] = {0}, response[1024] = {0};
	int transferred = 0;
	request[0] = operation;
	request[1] = operation >> 8;
	request[2] = 0x34;
	request[3] = 0x12;
	write32(request + 4, size);
	write32(request + 8, address);
	if (legacy_transfer(usb, 0x04, request, sizeof(request), &transferred) || transferred != sizeof(request)) return -1;
	int reply_size = usb->packets[0x83];
	if (reply_size < 12 || reply_size > (int)sizeof(response)) return -1;
	if (legacy_transfer(usb, 0x83, response, reply_size, &transferred) || transferred < 12 ||
		(operation ? read16(response) != 0x0808 : read16(response) != 0 || read16(response + 2) != 0x1234)) {
		logger(LL_ERROR, "Legacy recovery request 0x%04x failed\n", operation);
		return -1;
	}
	return 0;
}

static int legacy_open(struct legacy_usb *usb, struct idevicerestore_client_t *client)
{
	memset(usb, 0, sizeof(*usb));
	if (irecv_open_with_ecid(&usb->handle, 0) != IRECV_E_SUCCESS) return -1;
	irecv_device_t device = legacy_device(usb->handle, &usb->release);
	if (!device || !client->device || strcmp(device->product_type, client->device->product_type)) return -1;
	unsigned char header[9];
	if (irecv_usb_control_transfer(usb->handle, 0x80, 6, 0x0200, 0, header, sizeof(header), 1000) != sizeof(header)) return -1;
	unsigned int size = read16(header + 2);
	if (size < sizeof(header) || size > 4096) return -1;
	unsigned char *config = malloc(size);
	if (!config) return -1;
	int result = -1;
	if (irecv_usb_control_transfer(usb->handle, 0x80, 6, 0x0200, 0, config, size, 1000) != (int)size) goto out;
	int selected = 0;
	for (unsigned int offset = 0; offset + 2 <= size;) {
		unsigned char *d = config + offset;
		if (d[0] < 2 || offset + d[0] > size) goto out;
		if (d[1] == 4 && d[0] >= 9) selected = d[2] == 0 && d[3] == 0;
		if (selected && d[1] == 5 && d[0] >= 7) {
			usb->types[d[2]] = d[3] & 3;
			usb->packets[d[2]] = read16(d + 4) & 0x7ff;
		}
		offset += d[0];
	}
	unsigned char endpoints[] = {0x04, 0x83, 0x02, 0x05};
	for (unsigned int i = 0; i < sizeof(endpoints); i++) {
		unsigned int ep = endpoints[i];
		if (!usb->packets[ep] || (usb->types[ep] != 2 && usb->types[ep] != 3)) goto out;
	}
	/* Initialize iBoot-159's console worker before sending commands. */
	result = legacy_request(usb, 0, 0, 0);
out:
	free(config);
	return result;
}

static int legacy_command(struct legacy_usb *usb, const char *command)
{
	size_t length = strlen(command);
	if (!length || length > 4094) return -1;
	unsigned int size = (length + 2 + 15) & ~15u;
	unsigned char *buffer = calloc(1, size);
	if (!buffer) return -1;
	memcpy(buffer, command, length);
	buffer[length] = '\n';
	int transferred = 0;
	int result = legacy_request(usb, 0x0803, size, 0);
	if (!result) {
		result = legacy_transfer(usb, 0x02, buffer, size, &transferred);
		if (transferred != (int)size) result = -1;
	}
	free(buffer);
	return result;
}

struct legacy_image {
	const char *name;
	uint32_t address;
	uint32_t limit;
	void *data;
	size_t size;
};

static int legacy_prepare_component(struct idevicerestore_client_t *client, plist_t identity, struct legacy_image *image)
{
	char *path = NULL;
	if (build_identity_get_component_path(identity, image->name, &path) < 0) return -1;
	int result = extract_component(client->ipsw, path, &image->data, &image->size);
	free(path);
	if (result < 0 || !image->data || !image->size || image->size > image->limit - image->address) {
		logger(LL_ERROR, "Invalid %s for the iPhone OS 1 upload region\n", image->name);
		return -1;
	}
	return 0;
}

static int legacy_component(struct legacy_usb *usb, struct idevicerestore_client_t *client, struct legacy_image *image)
{
	logger(LL_INFO, "Sending %s (%zu bytes) to 0x%08x...\n", image->name, image->size, image->address);
	int result = legacy_request(usb, 0x0805, image->size, image->address);
	register_progress('LGCY', "Uploading");
	for (size_t offset = 0; !result && offset < image->size;) {
		if (client->flags & FLAG_QUIT) { result = -1; break; }
		size_t chunk = usb->types[0x05] == 3 ? 512 : 16384;
		if (chunk > image->size - offset) chunk = image->size - offset;
		int transferred = 0;
		result = legacy_transfer(usb, 0x05, (unsigned char*)image->data + offset, chunk, &transferred);
		if (transferred <= 0 || (size_t)transferred > chunk) { result = -1; break; }
		offset += transferred;
		set_progress('LGCY', (double)offset / image->size);
	}
	finalize_progress('LGCY');
	if (!result) {
		/* setpicture and go use the filesize environment variable. */
		char command[64];
		snprintf(command, sizeof(command), "setenv filesize %zu", image->size);
		result = legacy_command(usb, command);
	}
	return result;
}

static unsigned int legacy_target_release(struct idevicerestore_client_t *client)
{
	plist_t devices = plist_dict_get_item(client->build_manifest, "DeviceMap");
	for (uint32_t i = 0; i < plist_array_get_size(devices); i++) {
		plist_t device = plist_array_get_item(devices, i);
		const char *board = plist_get_string_ptr(plist_dict_get_item(device, "BoardConfig"), NULL);
		if (board && !strcasecmp(board, client->device->hardware_model)) {
			uint64_t release = 0;
			plist_get_uint_val(plist_dict_get_item(device, "DeviceReleaseNumber"), &release);
			return release & 0xffff;
		}
	}
	return 0;
}

static int legacy_prepare_recovery(struct legacy_usb *usb, struct idevicerestore_client_t *client, plist_t identity)
{
	unsigned int target = legacy_target_release(client);
	if (!target || (usb->release & 0xff) >= (target & 0xff)) return 0;
	/* The low byte of DeviceReleaseNumber identifies the recovery revision. */
	struct legacy_image ibec = { "iBEC", 0x09000000, 0x0b000000, NULL, 0 };
	int result = legacy_prepare_component(client, identity, &ibec);
	if (!result) {
		logger(LL_INFO, "Updating recovery bootloader from 0x%04x to 0x%04x with iBEC...\n", usb->release, target);
		result = legacy_component(usb, client, &ibec);
	}
	free(ibec.data);
	if (result) return -1;
	usleep(500000);
	result = legacy_command(usb, "go");
	irecv_close(usb->handle);
	usb->handle = NULL;
	if (result) return -1;
	logger(LL_INFO, "Waiting for the target recovery bootloader...\n");
	time_t deadline = time(NULL) + 60;
	while (!(client->flags & FLAG_QUIT) && time(NULL) < deadline) {
		irecv_client_t handle = NULL;
		if (irecv_open_with_ecid(&handle, 0) == IRECV_E_SUCCESS) {
			unsigned int release = 0;
			irecv_device_t device = legacy_device(handle, &release);
			irecv_close(handle);
			if (device && !strcmp(device->product_type, client->device->product_type) &&
				(release & 0xff) >= (target & 0xff)) {
				return legacy_open(usb, client);
			}
		}
		usleep(250000);
	}
	logger(LL_ERROR, "Target iBEC did not reconnect in recovery mode\n");
	return -1;
}

int legacy_recovery_restore(struct idevicerestore_client_t *client, plist_t identity)
{
	struct legacy_usb usb = {0};
	struct legacy_image images[] = {
		{ "RestoreRamDisk", 0x08000000, 0x0a000000, NULL, 0 },
		{ "RestoreDeviceTree", 0x0af00000, 0x0b000000, NULL, 0 },
		{ "RestoreKernelCache", 0x0a000000, 0x0af00000, NULL, 0 },
		{ "RestoreLogo", 0x09000000, 0x0a000000, NULL, 0 }
	};
	unsigned int image_count = build_identity_has_component(identity, "RestoreLogo") ? 4 : 3;
	int result = -1;
	char command[512];
	const char *args = client->restore_boot_args ? client->restore_boot_args : "rd=md0 nand-enable-reformat=1 -progress serial=3";
	int command_size = snprintf(command, sizeof(command), "setenv boot-args %s", args);
	if (command_size < 0 || command_size >= (int)sizeof(command)) goto out;
	for (unsigned int i = 0; i < image_count; i++) {
		if ((client->flags & FLAG_QUIT) || legacy_prepare_component(client, identity, &images[i]) < 0) goto out;
	}
	result = legacy_open(&usb, client);
	if (result < 0) goto out;
	logger(LL_INFO, "Using iPhone OS 1 recovery protocol\n");
	result = legacy_command(&usb, "setenv auto-boot false");
	if (!result) result = legacy_command(&usb, "saveenv");
	if (!result) result = legacy_prepare_recovery(&usb, client, identity);
	if (result) goto out;
	if (image_count == 4) {
		/* Display the logo before the ramdisk overwrites its upload buffer. */
		result = legacy_component(&usb, client, &images[3]);
		if (result) goto out;
		result = legacy_command(&usb, "setpicture 0");
		if (result) goto out;
		usleep(500000);
		result = legacy_command(&usb, "bgcolor 0 0 0");
		if (result) goto out;
	}
	result = legacy_command(&usb, command);
	if (result) goto out;
	result = legacy_component(&usb, client, &images[0]);
	if (result) goto out;
	snprintf(command, sizeof(command), "ramdisk 0x%zx 0x08000000", images[0].size);
	result = legacy_command(&usb, command);
	if (result) goto out;
	result = legacy_component(&usb, client, &images[1]);
	if (result) goto out;
	snprintf(command, sizeof(command), "devicetree 0x%zx 0x0af00000", images[1].size);
	result = legacy_command(&usb, command);
	if (result) goto out;
	result = legacy_component(&usb, client, &images[2]);
	if (result || (client->flags & FLAG_QUIT)) { result = -1; goto out; }
	result = legacy_command(&usb, "bootx 0x0a000000");
out:
	if (usb.handle) irecv_close(usb.handle);
	for (unsigned int i = 0; i < sizeof(images)/sizeof(images[0]); i++) free(images[i].data);
	if (result) logger(LL_ERROR, "iPhone OS 1 recovery boot failed\n");
	return result;
}
