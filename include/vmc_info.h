#ifndef __VMC_INFO_H__
#define __VMC_INFO_H__

#include <stdint.h>

#define VMC_SYSTEM_UNKNOWN 0
#define VMC_SYSTEM_PS1     1
#define VMC_SYSTEM_PS2     2

typedef struct vmc_info {
	int system;
	uint64_t file_size;
	uint32_t raw_size;
	uint32_t pagesize;
	uint32_t pages_per_cluster;
	uint32_t clusters_per_card;
	int has_ecc;
	const char* format;
} vmc_info_t;

int vmc_get_info(const char* path, vmc_info_t* info);
const char* vmc_system_name(int system);

#endif
