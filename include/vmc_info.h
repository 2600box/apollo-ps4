#ifndef __VMC_INFO_H__
#define __VMC_INFO_H__

#include <stdint.h>

#define VMC_SYSTEM_UNKNOWN 0
#define VMC_SYSTEM_PS1     1
#define VMC_SYSTEM_PS2     2

#define VMC_PS1_SIGNATURE_NA              0
#define VMC_PS1_SIGNATURE_PRESENT         1
#define VMC_PS1_SIGNATURE_MISSING_BLANK   2
#define VMC_PS1_SIGNATURE_MISSING_UNKNOWN 3

typedef struct vmc_info {
	int system;
	uint64_t file_size;
	uint32_t raw_size;
	uint64_t embedded_offset;
	uint32_t embedded_size;
	uint32_t pagesize;
	uint32_t pages_per_cluster;
	uint32_t clusters_per_card;
	int has_ecc;
	int ps1_signature;
	const char* format;
	const char* container;
} vmc_info_t;

int vmc_get_info(const char* path, vmc_info_t* info);
const char* vmc_system_name(int system);

#endif
