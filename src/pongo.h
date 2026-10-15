#ifndef __pongo_h
#define __pongo_h

#include <stdint.h>

#include "idevicerestore.h"
#include "common.h"

// ipf
#define IPF_NONE                    (0)
#define IPF_SIG_CHECK_PATCH         (1 << 0)

enum AUTOBOOT_STAGE {
	NONE,
	SEND_SEP_MODULE,
	LOAD_SEP_MODULE,
	
	// get block
	GET_PTE_BLOCK,
	GET_SHC_BLOCK,
	
	SET_XARGS,
	
	// pwn SEPROM and get exec (A9(X) only)
	SEND_PTE,
	LOAD_PTE,
	PWN_SEPROM_PTE,
	
	// pwn SEPROM and jump to hanlder
	SEND_APIGM4TICKET,
	LOAD_APIGM4TICKET,
	SEND_APIGM4TICKET_HASH,
	LOAD_APIGM4TICKET_HASH,
	SEND_RSEP,
	LOAD_RSEP,
	SEND_SEP_PAYLOAD,
	LOAD_SEP_PAYLOAD,
	SEND_SHELLCODE,
	LOAD_SHELLCODE,
	SET_SEP_FLAG,
	PWN_SEPROM,
	
	// kpf for tethered downgrade (ios 10+)
	SEND_KPF_TETHERED,
	LOAD_KPF_TETHERED,
	SET_KPF_TETHERED,
	SEND_OVERLAY,
	LOAD_OVERLAY,
	EXEC_KPF_TETHERED,
	
	// cryptex1 nonce setter for ios 16+
	SEND_CRYPTEX1_NONCE_SETTER,
	LOAD_CRYPTEX1_NONCE_SETTER,
	SET_CRYPTEX1_NONCE_SEED,
	SEND_CRYPTEX1_NONCE_SEED_PATCH,
	
	// send boot(u)x
	SEND_BOOTUX,
	
	SEND_RESET,
	
	USB_TRANSFER_ERROR,
};

extern int send_pongo_image(struct idevicerestore_client_t* client);
extern int pongo_shell(struct idevicerestore_client_t* idr_client,
					   struct irecv_device *device,
					   irecv_client_t *pclient,
					   int g_just_boot_pongo,
					   int is_tethered,
					   unsigned int boot_delay);

#endif
