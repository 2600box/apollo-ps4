#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "vmc_info.h"

#define PS1CARD_RAW_SIZE 131072
#define PS1_RAW_SIZE PS1CARD_RAW_SIZE
#define PS1HD_HDR_SIZE 0x8000
#define PS1HD_HEADER_SIZE PS1HD_HDR_SIZE
#define PS1HD_SLOT_SANITY_CAP 128
#define PS2_MAGIC "Sony PS2 Memory Card Format "
#define PS1_BLANK_CHECK_SIZE 4096
#define PS1_EMBED_SCAN_LIMIT (16 * 1024 * 1024)
#define PS1_EMBED_SCAN_CHUNK (64 * 1024)

static void vmc_info_init(vmc_info_t* info)
{
	if (!info)
		return;

	memset(info, 0, sizeof(*info));
	info->format = "Unknown";
	info->ps1_signature = VMC_PS1_SIGNATURE_NA;
	info->signature_present = 0;
	info->container = NULL;
}

static uint16_t read_le16(const uint8_t* ptr)
{
	return (uint16_t) ptr[0] | ((uint16_t) ptr[1] << 8);
}

static uint32_t read_le32(const uint8_t* ptr)
{
	return (uint32_t) ptr[0] | ((uint32_t) ptr[1] << 8) | ((uint32_t) ptr[2] << 16) | ((uint32_t) ptr[3] << 24);
}

int pfs_parse_sealedkey(const char* path, pfs_sealedkey_info_t* out)
{
	uint8_t data[96];
	FILE* fp;
	long size;

	if (!path || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseeko(fp, 0, SEEK_END) < 0)
	{
		fclose(fp);
		return 0;
	}

	size = ftello(fp);
	if (size != (long) sizeof(data) || fseeko(fp, 0, SEEK_SET) < 0)
	{
		fclose(fp);
		return 0;
	}

	if (fread(data, 1, sizeof(data), fp) != sizeof(data))
	{
		fclose(fp);
		return 0;
	}

	fclose(fp);

	if (memcmp(data, "pfsSKKey", 8) != 0)
		return 0;

	out->keyset = read_le16(data + 0x08);
	memcpy(out->iv, data + 0x10, sizeof(out->iv));
	memcpy(out->enc_key, data + 0x20, sizeof(out->enc_key));
	memcpy(out->hmac, data + 0x40, sizeof(out->hmac));
	out->valid = 1;
	return 1;
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

static int detect_ps1hd_vmc_container(const uint8_t* hdr, size_t hdr_size, uint64_t size, vmc_info_t* info)
{
	if (!hdr || !info)
		return 0;

	if (hdr_size < 0x2C || size <= PS1HD_HDR_SIZE)
		return 0;

	/*
	 * PS1HD virtual memory cards embedded in PS4 save images are wrapped in a
	 * container header and don't expose the raw "MC" signature at file offset 0.
	 * We identify this wrapper using its stable header fields.
	 */
	if (read_le32(hdr + 0x00) == 1 && read_le32(hdr + 0x20) == PS1HD_HDR_SIZE && read_le32(hdr + 0x24) == 1 && read_le32(hdr + 0x28) == 1)
	{
		uint64_t payload_size;
		uint64_t slots;

		if ((size - PS1HD_HDR_SIZE) % PS1CARD_RAW_SIZE != 0)
			return 0;

		payload_size = size - PS1HD_HDR_SIZE;
		slots = payload_size / PS1CARD_RAW_SIZE;
		if (slots == 0 || slots > PS1HD_SLOT_SANITY_CAP)
			return 0;

		info->system = VMC_SYSTEM_PS1;
		info->raw_size = PS1CARD_RAW_SIZE;
		info->ps1_signature = VMC_PS1_SIGNATURE_MISSING_UNKNOWN;
		info->embedded_slots = (uint32_t) slots;
		info->format = "PS1HD VMC container";
		return 1;
	}

	return 0;
}

static int read_ps1_signature_at(FILE* fp, uint64_t file_size, uint64_t offset)
{
	uint8_t sig[2];

	if (!fp || offset + sizeof(sig) > file_size)
		return 0;

	if (fseeko(fp, (off_t) offset, SEEK_SET) < 0)
		return 0;

	if (fread(sig, 1, sizeof(sig), fp) != sizeof(sig))
		return 0;

	return (sig[0] == 'M' && sig[1] == 'C');
}

static void fill_ps1hd_slot_info(FILE* fp, vmc_info_t* info, uint32_t slot)
{
	uint64_t slot_offset;
	int sig_at_start;
	int sig_at_80;

	if (!info)
		return;

	info->embedded_slot = slot;
	slot_offset = PS1HD_HDR_SIZE + ((uint64_t) slot * PS1CARD_RAW_SIZE);
	info->embedded_offset = slot_offset;
	info->embedded_size = PS1CARD_RAW_SIZE;

	sig_at_start = read_ps1_signature_at(fp, info->file_size, slot_offset);
	sig_at_80 = read_ps1_signature_at(fp, info->file_size, slot_offset + 0x80);

	if (sig_at_start || sig_at_80)
	{
		info->signature_present = 1;
		info->ps1_signature = VMC_PS1_SIGNATURE_PRESENT;
	}
	else
	{
		info->signature_present = 0;
		info->ps1_signature = VMC_PS1_SIGNATURE_MISSING_UNKNOWN;
	}
}

static int slot_looks_high_entropy(FILE* fp, uint64_t off)
{
	uint8_t block[4096];
	uint32_t hist[256] = {0};
	size_t i;
	unsigned distinct = 0;
	unsigned zeros_or_ff = 0;

	if (!fp)
		return 0;

	if (fseeko(fp, (off_t) off, SEEK_SET) < 0)
		return 0;

	if (fread(block, 1, sizeof(block), fp) != sizeof(block))
		return 0;

	for (i = 0; i < sizeof(block); i++)
	{
		hist[block[i]]++;
		if (block[i] == 0x00 || block[i] == 0xFF)
			zeros_or_ff++;
	}

	for (i = 0; i < 256; i++)
	{
		if (hist[i] != 0)
			distinct++;
	}

	if (distinct > 200 && zeros_or_ff * 50 < sizeof(block))
		return 1;

	return 0;
}

static int has_suffix(const char* path, const char* suffix)
{
	size_t path_len;
	size_t suffix_len;

	if (!path || !suffix)
		return 0;

	path_len = strlen(path);
	suffix_len = strlen(suffix);
	if (path_len < suffix_len)
		return 0;

	return (strcmp(path + path_len - suffix_len, suffix) == 0);
}

static int make_bin_candidate(char* out, size_t out_size, const char* base)
{
	size_t base_len;

	if (!out || !base || out_size == 0)
		return 0;

	base_len = strlen(base);
	if (base_len + 4 >= out_size)
		return 0;

	memcpy(out, base, base_len);
	memcpy(out + base_len, ".bin", 5);
	return 1;
}

static void detect_companion_sealedkey(const char* path, vmc_info_t* info)
{
	char candidate[256];
	char no_ext[256];
	const char* slash;
	const char* dot;
	pfs_sealedkey_info_t sk;

	if (!path || !info)
		return;

	if (!(has_suffix(path, ".VMC") || has_suffix(path, ".vmc")))
		return;

	slash = strrchr(path, '/');
	dot = strrchr(path, '.');
	if (dot && (!slash || dot > slash))
	{
		size_t n = (size_t) (dot - path);
		if (n >= sizeof(no_ext))
			n = sizeof(no_ext) - 1;
		memcpy(no_ext, path, n);
		no_ext[n] = '\0';
		if (make_bin_candidate(candidate, sizeof(candidate), no_ext) && pfs_parse_sealedkey(candidate, &sk) && sk.valid)
		{
			snprintf(info->sealedkey_path, sizeof(info->sealedkey_path), "%s", candidate);
			return;
		}
	}

	if (make_bin_candidate(candidate, sizeof(candidate), path) && pfs_parse_sealedkey(candidate, &sk) && sk.valid)
		snprintf(info->sealedkey_path, sizeof(info->sealedkey_path), "%s", candidate);
}

static int validate_embedded_ps1_signature(FILE* fp, uint64_t file_size, uint64_t sig_offset)
{
	uint8_t block[0x200];
	size_t read;
	size_t i;
	unsigned non_zero = 0;

	if (!fp || sig_offset + sizeof(block) > file_size)
		return 0;

	if (fseeko(fp, (off_t) sig_offset, SEEK_SET) < 0)
		return 0;

	read = fread(block, 1, sizeof(block), fp);
	if (read != sizeof(block))
		return 0;

	if (block[0] != 'M' || block[1] != 'C')
		return 0;

	for (i = 0; i < read; i++)
	{
		if (block[i] != 0x00)
			non_zero++;
	}

	return (non_zero > 16);
}

static int validate_embedded_ps1_region(FILE* fp, uint64_t file_size, uint64_t card_offset)
{
	uint8_t block[0x1000];
	uint32_t hist[256] = {0};
	size_t read;
	size_t i;
	uint32_t max_count = 0;
	unsigned non_zero = 0;
	unsigned non_ff = 0;

	if (!fp || card_offset + PS1CARD_RAW_SIZE > file_size)
		return 0;

	if (fseeko(fp, (off_t) card_offset, SEEK_SET) < 0)
		return 0;

	read = fread(block, 1, sizeof(block), fp);
	if (read != sizeof(block))
		return 0;

	for (i = 0; i < read; i++)
	{
		hist[block[i]]++;
		if (block[i] != 0x00)
			non_zero++;
		if (block[i] != 0xFF)
			non_ff++;
	}

	for (i = 0; i < 256; i++)
	{
		if (hist[i] > max_count)
			max_count = hist[i];
	}

	/*
	 * Uniform/random-like 4 KiB data has byte frequencies clustered around
	 * ~16 occurrences per symbol. A real PS1 memory-card region is more
	 * structured and should have noticeable peaks.
	 */
	if (max_count < 256)
		return 0;

	if (non_zero < 32 || non_ff < 32)
		return 0;

	return 1;
}

static int find_embedded_ps1_raw(FILE* fp, uint64_t file_size, uint64_t* out_off)
{
	uint8_t chunk[PS1_EMBED_SCAN_CHUNK + 1];
	uint64_t scan_limit;
	uint64_t base = 0;
	int has_prev = 0;

	if (!fp || !out_off || file_size < PS1CARD_RAW_SIZE)
		return 0;

	scan_limit = (file_size < PS1_EMBED_SCAN_LIMIT) ? file_size : PS1_EMBED_SCAN_LIMIT;

	if (fseeko(fp, 0, SEEK_SET) < 0)
		return 0;

	while (base < scan_limit)
	{
		size_t to_read;
		size_t got;
		size_t scan_len;
		size_t i;

		to_read = PS1_EMBED_SCAN_CHUNK;
		if (base + to_read > scan_limit)
			to_read = (size_t) (scan_limit - base);

		got = fread(chunk + (has_prev ? 1 : 0), 1, to_read, fp);
		if (got != to_read)
			return 0;

		scan_len = got + (has_prev ? 1 : 0);

		for (i = 0; i + 1 < scan_len; i++)
		{
			uint64_t sig_off;

			if (chunk[i] != 'M' || chunk[i + 1] != 'C')
				continue;

			sig_off = base - (has_prev ? 1 : 0) + i;

			if (sig_off + PS1CARD_RAW_SIZE <= file_size &&
				validate_embedded_ps1_signature(fp, file_size, sig_off) &&
				validate_embedded_ps1_region(fp, file_size, sig_off))
			{
				*out_off = sig_off;
				return 1;
			}

			if (sig_off >= 0x80 &&
				(sig_off - 0x80) + PS1CARD_RAW_SIZE <= file_size &&
				validate_embedded_ps1_signature(fp, file_size, sig_off) &&
				validate_embedded_ps1_region(fp, file_size, sig_off - 0x80))
			{
				*out_off = sig_off - 0x80;
				return 1;
			}
		}

		if (scan_len > 0)
		{
			chunk[0] = chunk[scan_len - 1];
			has_prev = 1;
		}

		base += got;

		if (fseeko(fp, (off_t) base, SEEK_SET) < 0)
			return 0;
	}

	return 0;
}


int vmc_read_embedded_slot(const char* path, uint32_t slot, uint8_t* buf, size_t buf_len)
{
	FILE* fp;
	uint8_t hdr[0x2C] = {0};
	uint64_t size;
	uint64_t slots;
	uint64_t slot_offset;

	if (!path || !buf || buf_len < PS1_RAW_SIZE)
		return 0;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseeko(fp, 0, SEEK_END) < 0)
	{
		fclose(fp);
		return 0;
	}

	size = (uint64_t) ftello(fp);
	if (size <= PS1HD_HEADER_SIZE || fseeko(fp, 0, SEEK_SET) < 0)
	{
		fclose(fp);
		return 0;
	}

	if (fread(hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
	{
		fclose(fp);
		return 0;
	}

	if (!(read_le32(hdr + 0x00) == 1 && read_le32(hdr + 0x20) == PS1HD_HEADER_SIZE && read_le32(hdr + 0x24) == 1 && read_le32(hdr + 0x28) == 1))
	{
		fclose(fp);
		return 0;
	}

	if ((size - PS1HD_HEADER_SIZE) % PS1_RAW_SIZE != 0)
	{
		fclose(fp);
		return 0;
	}

	slots = (size - PS1HD_HEADER_SIZE) / PS1_RAW_SIZE;
	if (slot >= slots)
	{
		fclose(fp);
		return 0;
	}

	slot_offset = PS1HD_HEADER_SIZE + ((uint64_t) slot * PS1_RAW_SIZE);
	if (fseeko(fp, (off_t) slot_offset, SEEK_SET) < 0)
	{
		fclose(fp);
		return 0;
	}

	if (fread(buf, 1, PS1_RAW_SIZE, fp) != PS1_RAW_SIZE)
	{
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return 1;
}

int vmc_dump_embedded_slot(const char* path, uint32_t slot, const char* outfile)
{
	uint8_t slot_data[PS1_RAW_SIZE];
	FILE* out;

	if (!path || !outfile)
		return 0;

	if (!vmc_read_embedded_slot(path, slot, slot_data, sizeof(slot_data)))
		return 0;

	out = fopen(outfile, "wb");
	if (!out)
		return 0;

	if (fwrite(slot_data, 1, sizeof(slot_data), out) != sizeof(slot_data))
	{
		fclose(out);
		return 0;
	}

	fclose(out);
	return 1;
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

int vmc_get_info_slot(const char* path, vmc_info_t* info, uint32_t slot)
{
	uint8_t hdr[0x200] = {0};
	FILE* fp;
	size_t n;

	if (!path || !info)
		return 0;

	vmc_info_init(info);

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
		info->signature_present = (info->ps1_signature == VMC_PS1_SIGNATURE_PRESENT) ? 1 : 0;
		fclose(fp);
		return 1;
	}

	if (detect_ps1hd_vmc_container(hdr, n, info->file_size, info))
	{
		if (slot >= info->embedded_slots)
		{
			fclose(fp);
			return 0;
		}

		fill_ps1hd_slot_info(fp, info, slot);
		fclose(fp);
		return 1;
	}

	{
		uint64_t embedded_offset;

		if (find_embedded_ps1_raw(fp, info->file_size, &embedded_offset))
		{
			info->system = VMC_SYSTEM_PS1;
			info->format = "PS1 Memory Card";
			info->container = "Embedded/Container VMC";
			info->raw_size = PS1CARD_RAW_SIZE;
			info->embedded_offset = embedded_offset;
			info->embedded_size = PS1CARD_RAW_SIZE;
			info->ps1_signature = VMC_PS1_SIGNATURE_PRESENT;

			fclose(fp);
			return 1;
		}
	}

	fclose(fp);

	return 0;
}

int vmc_get_info(const char* path, vmc_info_t* info)
{
	uint8_t hdr[0x200] = {0};
	FILE* fp;
	size_t n;

	if (!path || !info)
		return 0;

	vmc_info_init(info);

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
		info->signature_present = (info->ps1_signature == VMC_PS1_SIGNATURE_PRESENT) ? 1 : 0;
		fclose(fp);
		return 1;
	}

	if (detect_ps1hd_vmc_container(hdr, n, info->file_size, info))
	{
		uint32_t sample_slots = info->embedded_slots;

		fill_ps1hd_slot_info(fp, info, 0);
		uint32_t i;
		uint32_t missing_count = 0;
		uint32_t high_entropy_count = 0;

		if (sample_slots > 26)
			sample_slots = 26;

		for (i = 0; i < sample_slots; i++)
		{
			uint64_t slot_offset = PS1HD_HDR_SIZE + ((uint64_t) i * PS1CARD_RAW_SIZE);
			int signature_present =
				read_ps1_signature_at(fp, info->file_size, slot_offset) ||
				read_ps1_signature_at(fp, info->file_size, slot_offset + 0x80);

			if (!signature_present)
			{
				missing_count++;
				if (slot_looks_high_entropy(fp, slot_offset))
					high_entropy_count++;
			}
		}

		if (sample_slots > 0 && missing_count == sample_slots && high_entropy_count >= (sample_slots * 3 / 4))
		{
			info->slot_payload_suspect_encrypted = 1;
			info->ps1_signature = VMC_PS1_SIGNATURE_ENCRYPTED;
			info->container = "PS1HD VMC container (payload appears encrypted/protected)";
		}
		else
		{
			info->container = "PS1HD VMC container";
		}

		detect_companion_sealedkey(path, info);
		fclose(fp);
		return 1;
	}

	{
		uint64_t embedded_offset;

		if (find_embedded_ps1_raw(fp, info->file_size, &embedded_offset))
		{
			info->system = VMC_SYSTEM_PS1;
			info->format = "PS1 Memory Card";
			info->container = "Embedded/Container VMC";
			info->raw_size = PS1CARD_RAW_SIZE;
			info->embedded_offset = embedded_offset;
			info->embedded_size = PS1CARD_RAW_SIZE;
			info->ps1_signature = VMC_PS1_SIGNATURE_PRESENT;
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}
