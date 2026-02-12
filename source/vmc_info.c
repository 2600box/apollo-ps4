#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "vmc_info.h"

#define PS1CARD_RAW_SIZE 131072
#define PS2_MAGIC "Sony PS2 Memory Card Format "
#define PS1_BLANK_CHECK_SIZE 4096

static uint16_t read_le16(const uint8_t* ptr)
{
	return (uint16_t) ptr[0] | ((uint16_t) ptr[1] << 8);
}

static uint32_t read_le32(const uint8_t* ptr)
{
	return (uint32_t) ptr[0] | ((uint32_t) ptr[1] << 8) | ((uint32_t) ptr[2] << 16) | ((uint32_t) ptr[3] << 24);
}

static int is_ps1_headered_size(uint64_t size)
{
	return (size == 0x20040 || size == 0x20080 || size == 0x200A0 || size == 0x20F40);
}

static int check_ps1_blank_prefix(FILE* fp, uint64_t size)
{
	uint8_t block[256];
	uint64_t remaining;
	int all_zero = 1;
	int all_ff = 1;

	if (!fp)
		return 0;

	remaining = (size < PS1_BLANK_CHECK_SIZE) ? size : PS1_BLANK_CHECK_SIZE;
	if (remaining == 0)
		return 0;

	if (fseeko(fp, 0, SEEK_SET) < 0)
		return 0;

	while (remaining > 0)
	{
		size_t chunk = (remaining > sizeof(block)) ? sizeof(block) : (size_t) remaining;
		size_t read = fread(block, 1, chunk, fp);

		if (read != chunk)
			return 0;

		for (size_t i = 0; i < read; i++)
		{
			if (block[i] != 0x00)
				all_zero = 0;
			if (block[i] != 0xFF)
				all_ff = 0;

			if (!all_zero && !all_ff)
				return 0;
		}

		remaining -= read;
	}

	return 1;
}

static int detect_ps1_vmc(FILE* fp, const uint8_t* hdr, size_t hdr_size, uint64_t size, vmc_info_t* info)
{
	if (!info)
		return 0;

	if (size == PS1CARD_RAW_SIZE)
	{
		info->system = VMC_SYSTEM_PS1;
		info->raw_size = PS1CARD_RAW_SIZE;

		if (hdr_size >= 2 && hdr[0] == 'M' && hdr[1] == 'C')
		{
			info->ps1_signature = VMC_PS1_SIGNATURE_PRESENT;
			info->format = "PS1 Memory Card";
		}
		else if (check_ps1_blank_prefix(fp, size))
		{
			info->ps1_signature = VMC_PS1_SIGNATURE_MISSING_BLANK;
			info->format = "PS1 Memory Card (unformatted/blank)";
		}
		else
		{
			info->ps1_signature = VMC_PS1_SIGNATURE_MISSING_UNKNOWN;
			info->format = "PS1 Memory Card (unknown signature)";
		}

		return 1;
	}

	if (is_ps1_headered_size(size) && hdr_size >= 0x82 && hdr[0x80] == 'M' && hdr[0x81] == 'C')
	{
		info->system = VMC_SYSTEM_PS1;
		info->raw_size = PS1CARD_RAW_SIZE;
		info->ps1_signature = VMC_PS1_SIGNATURE_PRESENT;
		info->format = "PS1 Memory Card";
		return 1;
	}

	return 0;
}

const char* vmc_system_name(int system)
{
	switch (system)
	{
		case VMC_SYSTEM_PS1:
			return "PS1";
		case VMC_SYSTEM_PS2:
			return "PS2";
		default:
			return "Unknown";
	}
}

int vmc_get_info(const char* path, vmc_info_t* info)
{
	uint8_t hdr[0x200] = {0};
	FILE* fp;
	size_t n;

	if (!path || !info)
		return 0;

	memset(info, 0, sizeof(*info));
	info->format = "Unknown";
	info->ps1_signature = VMC_PS1_SIGNATURE_NA;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseeko(fp, 0, SEEK_END) < 0)
	{
		fclose(fp);
		return 0;
	}

	info->file_size = (uint64_t) ftello(fp);
	if (fseeko(fp, 0, SEEK_SET) < 0)
	{
		fclose(fp);
		return 0;
	}

	n = fread(hdr, 1, sizeof(hdr), fp);
	if (n < 0x90)
	{
		fclose(fp);
		return 0;
	}

	if (!memcmp(hdr, PS2_MAGIC, sizeof(PS2_MAGIC) - 1))
	{
		uint64_t raw_size;

		info->system = VMC_SYSTEM_PS2;
		info->format = "PS2 VMC";
		info->pagesize = read_le16(hdr + 0x28);
		info->pages_per_cluster = read_le16(hdr + 0x2A);
		info->clusters_per_card = read_le32(hdr + 0x30);

		raw_size = (uint64_t) info->pagesize * info->pages_per_cluster * info->clusters_per_card;
		if (raw_size > UINT32_MAX)
		{
			fclose(fp);
			return 0;
		}

		info->raw_size = (uint32_t) raw_size;
		if (raw_size > 0 && info->file_size == raw_size + (raw_size / 32))
			info->has_ecc = 1;
		fclose(fp);

		return 1;
	}

	if (detect_ps1_vmc(fp, hdr, n, info->file_size, info))
	{
		fclose(fp);
		return 1;
	}

	fclose(fp);

	return 0;
}
