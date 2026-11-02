#ifndef IDEVICERESTORE_LEGACY_H
#define IDEVICERESTORE_LEGACY_H

#include "common.h"

int legacy_is_ios1(struct idevicerestore_client_t *client);
int legacy_set_boot_args(struct idevicerestore_client_t *client);
irecv_device_t legacy_recovery_probe(struct idevicerestore_client_t *client);
int legacy_recovery_restore(struct idevicerestore_client_t *client, plist_t identity);

#endif
