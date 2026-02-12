#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <math.h>

#include <openssl/evp.h>

#include "vmc_info.h"

#define SLOT_SUMMARY_LIMIT 10
#define PS1HD_HEADER_SIZE 0x8000
#define PS1_RAW_SIZE 0x20000
#define PS1_BLOCK_SIZE 8192
#define PS1_SLOT_COUNT 15
#define PS1_DIR_ENTRY_SIZE 128
#define PS1_DIR_OFFSET 0x80

static void print_usage(const char* argv0)
{
	fprintf(stderr, "Usage: %s [--slot N] [--list-slots] [--fingerprint] [--dump-slot N OUTFILE] [--decrypt OUTFILE] [--sealedkey PATH] [--rawkey PATH] <memory-card.vmc> [more...]\n", argv0);
	fprintf(stderr, "  --slot N            Target embedded slot N for slot-dependent operations (including --decrypt).\n");
	fprintf(stderr, "  --dump-slot N FILE  Dump embedded slot N; writes FILE only when valid .mcd, else FILE.raw/FILE.cand.\n");
	fprintf(stderr, "  --decrypt FILE      Decrypt targeted slot (--slot, default 0) to FILE when valid .mcd, else FILE.raw/FILE.cand.\n");
}

static uint64_t fnv1a64(const uint8_t* data, size_t len);
static int buffer_looks_high_entropy(const uint8_t* data, size_t len);
static int slot_has_signature(const uint8_t* slot_data);
static int score_ps1_slot_layout(const uint8_t* slot_data);
static void print_first16_hex_to(FILE* out, const uint8_t* data);
static void print_first16_hex(const uint8_t* data);

typedef enum mcd_verdict {
	MCD_NOT_MCD = 0,
	MCD_VALID = 1,
} mcd_verdict_t;

typedef struct mcd_validation {
	mcd_verdict_t verdict;
	double entropy_4k;
	int begins_with_mc;
	int plausible_dir_flags;
} mcd_validation_t;

static const size_t g_raw_key_sizes[] = {16, 32, 48};

typedef struct raw_key_blob {
	uint8_t data[64];
	size_t len;
	int valid;
} raw_key_blob_t;

static int raw_key_size_allowed(size_t size)
{
	size_t i;

	for (i = 0; i < sizeof(g_raw_key_sizes) / sizeof(g_raw_key_sizes[0]); i++)
	{
		if (g_raw_key_sizes[i] == size)
			return 1;
	}

	return 0;
}

static int read_file_size(const char* path, size_t* out_size)
{
	FILE* fp;
	long size;

	if (!path || !out_size)
		return 0;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseeko(fp, 0, SEEK_END) < 0)
	{
		fclose(fp);
		return 0;
	}

	size = ftello(fp);
	fclose(fp);
	if (size < 0)
		return 0;

	*out_size = (size_t) size;
	return 1;
}

static int read_file_bytes(const char* path, uint8_t* buf, size_t want, size_t* got)
{
	FILE* fp;
	long size;

	if (!path || !buf || !got)
		return 0;

	*got = 0;
	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseeko(fp, 0, SEEK_END) < 0)
	{
		fclose(fp);
		return 0;
	}

	size = ftello(fp);
	if (size < 0 || fseeko(fp, 0, SEEK_SET) < 0)
	{
		fclose(fp);
		return 0;
	}

	if ((size_t) size > want)
	{
		fclose(fp);
		return 0;
	}

	if (fread(buf, 1, (size_t) size, fp) != (size_t) size)
	{
		fclose(fp);
		return 0;
	}

	fclose(fp);
	*got = (size_t) size;
	return 1;
}

static void print_raw_key_info(const char* rawkey_path)
{
	uint8_t data[64];
	size_t len;
	uint64_t hash;

	if (!rawkey_path)
		return;

	if (!read_file_bytes(rawkey_path, data, sizeof(data), &len))
	{
		printf("Raw key: unreadable [%s]\n", rawkey_path);
		return;
	}

	if (!raw_key_size_allowed(len))
	{
		printf("Raw key: unsupported size (%zu bytes; expected 16/32/48) [%s]\n", len, rawkey_path);
		return;
	}

	hash = fnv1a64(data, len);
	printf("Raw key: present (%zu bytes) [%s]\n", len, rawkey_path);
	printf("Raw key fingerprint: first8=");
	for (size_t i = 0; i < 8; i++)
		printf("%02x", data[i]);
	printf(" last8=");
	for (size_t i = len - 8; i < len; i++)
		printf("%02x", data[i]);
	printf(" fnv1a64=%016" PRIx64 "\n", hash);
}

static int load_raw_key(const char* rawkey_path, raw_key_blob_t* out)
{
	if (!out)
		return 0;

	memset(out, 0, sizeof(*out));
	if (!rawkey_path)
		return 0;

	if (!read_file_bytes(rawkey_path, out->data, sizeof(out->data), &out->len))
		return 0;

	if (!raw_key_size_allowed(out->len))
		return 0;

	out->valid = 1;
	return 1;
}

static int decrypt_slot_xts(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key, size_t key_len, uint64_t sector_base, int tweak_be)
{
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* cipher = NULL;
	uint8_t iv[16];
	int out_len;
	size_t off;

	if (!in || !out || !key || len % 512 != 0)
		return 0;

	if (key_len == 32)
		cipher = EVP_aes_128_xts();
#ifdef EVP_aes_256_xts
	else if (key_len == 64)
		cipher = EVP_aes_256_xts();
#endif
	else
		return 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	for (off = 0; off < len; off += 512)
	{
		uint64_t sector = sector_base + (off / 512);
		size_t i;

		memset(iv, 0, sizeof(iv));
		for (i = 0; i < 8; i++)
		{
			uint8_t v = (uint8_t) ((sector >> (8 * i)) & 0xFF);
			iv[tweak_be ? (7 - i) : i] = v;
		}

		if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
		{
			EVP_CIPHER_CTX_free(ctx);
			return 0;
		}

		if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
		{
			EVP_CIPHER_CTX_free(ctx);
			return 0;
		}

		if (EVP_DecryptUpdate(ctx, out + off, &out_len, in + off, 512) != 1 || out_len != 512)
		{
			EVP_CIPHER_CTX_free(ctx);
			return 0;
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

static void build_key_variant(uint8_t out[32], const uint8_t in[32], int key_mode)
{
	int i;

	switch (key_mode)
	{
		case 1:
			memcpy(out, in + 16, 16);
			memcpy(out + 16, in, 16);
			break;
		case 2:
			for (i = 0; i < 16; i++)
			{
				out[i] = in[15 - i];
				out[16 + i] = in[31 - i];
			}
			break;
		case 3:
			for (i = 0; i < 32; i++)
				out[i] = in[31 - i];
			break;
		default:
			memcpy(out, in, 32);
			break;
	}
}

static int maybe_transform_slot_with_raw_key(uint8_t* slot_data, uint32_t slot_index, const raw_key_blob_t* raw_key)
{
	uint8_t candidate[PS1_RAW_SIZE];
	uint8_t best_candidate[PS1_RAW_SIZE];
	uint8_t key_variant[32];
	int best_score = -1;
	int mode;
	int key_mode_start;
	int key_mode_end;
	int key_mode;

	if (!slot_data || !raw_key || !raw_key->valid)
		return 0;

	if (raw_key->len == 32)
	{
		key_mode_start = 0;
		key_mode_end = 4;
	}
	else
	{
		key_mode_start = 0;
		key_mode_end = 1;
	}

	for (key_mode = key_mode_start; key_mode < key_mode_end; key_mode++)
	{
		if (raw_key->len == 32)
			build_key_variant(key_variant, raw_key->data, key_mode);

		for (mode = 0; mode < 4; mode++)
		{
			uint64_t sector_base = (mode & 1) ? (((uint64_t) PS1HD_HEADER_SIZE / 512) + ((uint64_t) slot_index * (PS1_RAW_SIZE / 512))) : ((uint64_t) slot_index * (PS1_RAW_SIZE / 512));
			int tweak_be = (mode & 2) ? 1 : 0;
			int score = 0;
			const uint8_t* key_data = (raw_key->len == 32) ? key_variant : raw_key->data;

			if (!decrypt_slot_xts(slot_data, candidate, sizeof(candidate), key_data, raw_key->len, sector_base, tweak_be))
				continue;

			score += score_ps1_slot_layout(candidate);
			if (!buffer_looks_high_entropy(candidate, 4096))
				score += 2;
			if (candidate[0] == 'M' && candidate[1] == 'C')
				score += 2;

			if (score > best_score)
			{
				memcpy(best_candidate, candidate, sizeof(best_candidate));
				best_score = score;
			}
		}
	}

	if (best_score >= 12)
	{
		memcpy(slot_data, best_candidate, sizeof(best_candidate));
		return 1;
	}

	return 0;
}

static int build_best_transformed_slot(const uint8_t* slot_data, uint32_t slot_index, const raw_key_blob_t* raw_key, uint8_t* best_candidate)
{
	uint8_t candidate[PS1_RAW_SIZE];
	uint8_t key_variant[32];
	int best_score = -1;
	int mode;
	int key_mode_start;
	int key_mode_end;
	int key_mode;

	if (!slot_data || !raw_key || !raw_key->valid || !best_candidate)
		return 0;

	if (raw_key->len == 32)
	{
		key_mode_start = 0;
		key_mode_end = 4;
	}
	else
	{
		key_mode_start = 0;
		key_mode_end = 1;
	}

	for (key_mode = key_mode_start; key_mode < key_mode_end; key_mode++)
	{
		if (raw_key->len == 32)
			build_key_variant(key_variant, raw_key->data, key_mode);

		for (mode = 0; mode < 4; mode++)
		{
			uint64_t sector_base = (mode & 1) ? (((uint64_t) PS1HD_HEADER_SIZE / 512) + ((uint64_t) slot_index * (PS1_RAW_SIZE / 512))) : ((uint64_t) slot_index * (PS1_RAW_SIZE / 512));
			int tweak_be = (mode & 2) ? 1 : 0;
			int score = 0;
			const uint8_t* key_data = (raw_key->len == 32) ? key_variant : raw_key->data;

			if (!decrypt_slot_xts(slot_data, candidate, sizeof(candidate), key_data, raw_key->len, sector_base, tweak_be))
				continue;

			score += score_ps1_slot_layout(candidate);
			if (!buffer_looks_high_entropy(candidate, 4096))
				score += 2;
			if (candidate[0] == 'M' && candidate[1] == 'C')
				score += 2;

			if (score > best_score)
			{
				memcpy(best_candidate, candidate, PS1_RAW_SIZE);
				best_score = score;
			}
		}
	}

	return best_score >= 0;
}

static double estimate_shannon_entropy(const uint8_t* data, size_t len)
{
	uint32_t hist[256] = {0};
	size_t i;
	double entropy = 0.0;

	if (!data || len == 0)
		return 0.0;

	for (i = 0; i < len; i++)
		hist[data[i]]++;

	for (i = 0; i < 256; i++)
	{
		double p;
		if (hist[i] == 0)
			continue;
		p = (double) hist[i] / (double) len;
		entropy -= p * (log(p) / log(2.0));
	}

	return entropy;
}

static int dir_frames_look_plausible(const uint8_t* slot_data)
{
	int i;
	int plausible = 0;

	if (!slot_data)
		return 0;

	for (i = 0; i < PS1_SLOT_COUNT; i++)
	{
		const uint8_t* dir = slot_data + PS1_DIR_OFFSET + (i * PS1_DIR_ENTRY_SIZE);
		uint8_t type = dir[0];

		if (type == 0xA0 || type == 0xA1 || type == 0xA2 || type == 0xA3 ||
			type == 0x50 || type == 0x51 || type == 0x52 || type == 0x53)
			plausible++;
	}

	return plausible >= 10;
}

static mcd_validation_t validate_mcd_buffer(const uint8_t* data, size_t len, const char* label, int verbose)
{
	mcd_validation_t out;

	memset(&out, 0, sizeof(out));
	if (!data || len != PS1_RAW_SIZE)
		return out;

	out.begins_with_mc = (data[0] == 'M' && data[1] == 'C');
	out.entropy_4k = estimate_shannon_entropy(data, 4096);
	out.plausible_dir_flags = dir_frames_look_plausible(data);
	out.verdict = out.begins_with_mc ? MCD_VALID : MCD_NOT_MCD;

	if (verbose)
	{
		printf("MCD check (%s):\n", label ? label : "buffer");
		printf("  first16: ");
		print_first16_hex(data);
		printf("\n");
		printf("  begins_with_MC: %s\n", out.begins_with_mc ? "yes" : "no");
		printf("  entropy(first4k): %.3f bits/byte (%s)\n", out.entropy_4k, out.entropy_4k > 7.6 ? "high" : "normal");
		printf("  plausible_directory_flags: %s\n", out.plausible_dir_flags ? "yes" : "no");
		printf("  verdict: %s\n", out.verdict == MCD_VALID ? "VALID_MCD" : "NOT_MCD");
	}

	return out;
}

static int write_buffer_file(const char* path, const uint8_t* data, size_t len)
{
	FILE* out;

	if (!path || !data)
		return 0;

	out = fopen(path, "wb");
	if (!out)
		return 0;

	if (fwrite(data, 1, len, out) != len)
	{
		fclose(out);
		return 0;
	}

	fclose(out);
	return 1;
}

static uint64_t fnv1a64(const uint8_t* data, size_t len)
{
	uint64_t hash = 1469598103934665603ULL;
	size_t i;

	for (i = 0; i < len; i++)
	{
		hash ^= data[i];
		hash *= 1099511628211ULL;
	}

	return hash;
}

static int buffer_looks_high_entropy(const uint8_t* data, size_t len)
{
	uint32_t hist[256] = {0};
	size_t i;
	unsigned distinct = 0;
	unsigned zeros_or_ff = 0;

	if (!data || len == 0)
		return 0;

	for (i = 0; i < len; i++)
	{
		hist[data[i]]++;
		if (data[i] == 0x00 || data[i] == 0xFF)
			zeros_or_ff++;
	}

	for (i = 0; i < 256; i++)
	{
		if (hist[i] != 0)
			distinct++;
	}

	return (distinct > 200 && zeros_or_ff * 50 < len);
}

static void print_first16_hex(const uint8_t* data)
{
	print_first16_hex_to(stdout, data);
}

static void print_first16_hex_to(FILE* out, const uint8_t* data)
{
	size_t i;
	if (!out)
		out = stdout;

	for (i = 0; i < 16; i++)
		fprintf(out, "%02x", data[i]);
}

static int slot_has_signature(const uint8_t* slot_data)
{
	if (!slot_data)
		return 0;

	if (slot_data[0] == 'M' && slot_data[1] == 'C')
		return 1;

	if (slot_data[0x80] == 'M' && slot_data[0x81] == 'C')
		return 1;

	return 0;
}

static int score_ps1_slot_layout(const uint8_t* slot_data)
{
	int i;
	int score = 0;
	int used_entries = 0;
	int plausible_entries = 0;

	if (!slot_data)
		return 0;

	if (slot_has_signature(slot_data))
		score += 8;

	for (i = 0; i < PS1_SLOT_COUNT; i++)
	{
		const uint8_t* dir = slot_data + PS1_DIR_OFFSET + (i * PS1_DIR_ENTRY_SIZE);
		uint8_t type = dir[0];
		uint32_t size_bytes;

		if (type == 0xA0 || type == 0xA1 || type == 0xA2 || type == 0x50 || type == 0x51 || type == 0x52 || type == 0x53)
			score += 1;

		if (!(type == 0x51 || type == 0xA1))
			continue;

		used_entries++;
		size_bytes = (uint32_t) dir[4] | ((uint32_t) dir[5] << 8) | ((uint32_t) dir[6] << 16);
		if (size_bytes >= PS1_BLOCK_SIZE && size_bytes <= (PS1_SLOT_COUNT * PS1_BLOCK_SIZE) && (size_bytes % PS1_BLOCK_SIZE) == 0)
		{
			plausible_entries++;
			score += 3;
		}
	}

	if (used_entries > 0 && plausible_entries == used_entries)
		score += 4;

	return score;
}

static void copy_ps1_text(char* out, size_t out_len, const uint8_t* src, size_t src_len)
{
	size_t i;
	size_t j = 0;

	if (!out || out_len == 0)
		return;

	for (i = 0; i < src_len && j + 1 < out_len; i++)
	{
		uint8_t ch = src[i];

		if (ch == 0x00)
			break;

		if (isprint(ch) || ch == ' ')
			out[j++] = (char) ch;
		else if (ch == '\n' || ch == '\r' || ch == '\t')
			out[j++] = ' ';
		else
			out[j++] = '.';
	}

	out[j] = '\0';
}

static void print_slot_save_details(const uint8_t* slot_data, uint32_t slot_number)
{
	int i;
	int any = 0;

	printf("slot %u saves:\n", slot_number);

	for (i = 0; i < PS1_SLOT_COUNT; i++)
	{
		const uint8_t* dir = slot_data + PS1_DIR_OFFSET + (i * PS1_DIR_ENTRY_SIZE);
		uint8_t type = dir[0];

		if (!(type == 0x51 || type == 0xA1))
			continue;

		{
			uint32_t size_bytes = (uint32_t) dir[4] | ((uint32_t) dir[5] << 8) | ((uint32_t) dir[6] << 16);
			uint32_t blocks = size_bytes / PS1_BLOCK_SIZE;
			char save_name[21] = {0};
			char product[11] = {0};
			char identifier[9] = {0};
			char title[65] = {0};
			const uint8_t* save_block = slot_data + ((size_t) (i + 1) * PS1_BLOCK_SIZE);

			memcpy(save_name, dir + 10, 20);
			save_name[20] = '\0';
			memcpy(product, dir + 12, 10);
			product[10] = '\0';
			memcpy(identifier, dir + 22, 8);
			identifier[8] = '\0';
			copy_ps1_text(title, sizeof(title), save_block + 4, 64);

			printf("  block %d: name=%s title=%s product=%s id=%s blocks=%u status=%s\n",
				i,
				save_name[0] ? save_name : "<empty>",
				title[0] ? title : "<unreadable>",
				product[0] ? product : "<n/a>",
				identifier[0] ? identifier : "<n/a>",
				blocks,
				(type == 0x51) ? "active" : "deleted");
			any = 1;
		}
	}

	if (!any)
		printf("  <no active save headers detected>\n");
}

static void print_ps1_signature(const vmc_info_t* info)
{
	switch (info->ps1_signature)
	{
		case VMC_PS1_SIGNATURE_PRESENT:
			printf("Signature: present\n");
			break;
		case VMC_PS1_SIGNATURE_MISSING_BLANK:
			printf("Signature: missing (treating as unformatted/blank PS1 raw card)\n");
			break;
		case VMC_PS1_SIGNATURE_MISSING_UNKNOWN:
			printf("Signature: missing\n");
			break;
		case VMC_PS1_SIGNATURE_ENCRYPTED:
			printf("Signature: missing (payload appears encrypted/protected; PS1 'MC' header not visible)\n");
			break;
		default:
			break;
	}
}

static int print_slot_summary(const char* path, uint32_t slots, int encrypted, int show_fingerprint, const raw_key_blob_t* raw_key)
{
	uint32_t i;
	uint32_t limit = slots;

	if (limit > SLOT_SUMMARY_LIMIT)
		limit = SLOT_SUMMARY_LIMIT;

	printf("Container header size: %u bytes\n", PS1HD_HEADER_SIZE);
	printf("Embedded card size: %u bytes\n", PS1_RAW_SIZE);
	printf("Embedded slots: %u\n", slots);

	for (i = 0; i < limit; i++)
	{
		uint8_t slot_buf[PS1_RAW_SIZE];
		int signature_present;

		if (!vmc_read_embedded_slot(path, i, slot_buf, sizeof(slot_buf)))
		{
			printf("slot %u: <read error>\n", i);
			continue;
		}

		(void) maybe_transform_slot_with_raw_key(slot_buf, i, raw_key);
		signature_present = slot_has_signature(slot_buf);

		if (!signature_present && encrypted)
			printf("slot %u: signature missing (high entropy)\n", i);
		else
			printf("slot %u: signature %s\n", i, signature_present ? "present" : "missing");
	}

	if (slots > limit)
		printf("...\n");

	for (i = 0; i < slots; i++)
	{
		uint8_t slot_buf[PS1_RAW_SIZE];

		if (!vmc_read_embedded_slot(path, i, slot_buf, sizeof(slot_buf)))
			continue;

		(void) maybe_transform_slot_with_raw_key(slot_buf, i, raw_key);

		print_slot_save_details(slot_buf, i);
	}

	if (show_fingerprint)
	{
		printf("Fingerprints (non-cryptographic hash: FNV-1a 64-bit):\n");
		for (i = 0; i < slots; i++)
		{
			uint8_t slot_buf[PS1_RAW_SIZE];
			uint64_t hash;
			int signature_present;
			int high_entropy;

			if (!vmc_read_embedded_slot(path, i, slot_buf, sizeof(slot_buf)))
			{
				printf("slot %u: <read error>\n", i);
				continue;
			}

			hash = fnv1a64(slot_buf, sizeof(slot_buf));
			(void) maybe_transform_slot_with_raw_key(slot_buf, i, raw_key);
			hash = fnv1a64(slot_buf, sizeof(slot_buf));
			signature_present = slot_has_signature(slot_buf);
			high_entropy = buffer_looks_high_entropy(slot_buf, 4096);

			printf("slot %u: first16=", i);
			print_first16_hex(slot_buf);
			printf("  hash64=%016" PRIx64 "  signature=%s  entropy=%s\n",
				hash,
				signature_present ? "present" : "missing",
				high_entropy ? "high" : "low");
		}
	}

	return 0;
}

static int print_vmc_info(const char* path, int has_slot, uint32_t slot, const char* sealedkey_override, const char* rawkey_override, int explicit_list_slots, int fingerprint)
{
	vmc_info_t info;
	pfs_sealedkey_info_t sk_info;
	raw_key_blob_t raw_key;
	int sealedkey_valid = 0;
	const char* sealedkey_path = NULL;
	int raw_key_loaded = 0;

	raw_key_loaded = load_raw_key(rawkey_override, &raw_key);

	if ((has_slot && !vmc_get_info_slot(path, &info, slot)) || (!has_slot && !vmc_get_info(path, &info)))
	{
		fprintf(stderr, "%s: failed to parse VMC file\n", path);
		return 1;
	}

	printf("File: %s\n", path);
	printf("System: %s\n", vmc_system_name(info.system));
	printf("Format: %s\n", info.format ? info.format : "Unknown");
	printf("Size: %" PRIu64 " bytes\n", info.file_size);

	if (info.system == VMC_SYSTEM_PS2)
	{
		printf("Page size: %u\n", info.pagesize);
		printf("Pages/cluster: %u\n", info.pages_per_cluster);
		printf("Clusters/card: %u\n", info.clusters_per_card);
		printf("Raw size: %u bytes\n", info.raw_size);
		printf("ECC: %s\n", info.has_ecc ? "present" : "not present");
	}
	else if (info.system == VMC_SYSTEM_PS1)
	{
		printf("Raw size: %u bytes\n", info.raw_size);

		(void) explicit_list_slots;

		if (!has_slot && info.embedded_slots > 0)
			print_slot_summary(path, info.embedded_slots, info.slot_payload_suspect_encrypted && !raw_key_loaded, fingerprint, raw_key_loaded ? &raw_key : NULL);

		if (info.embedded_slots > 0)
		{
			printf("Embedded slot: %u / %u\n", info.embedded_slot, info.embedded_slots - 1);
			printf("Embedded offset: %" PRIu64 " (0x%" PRIx64 ")\n", info.embedded_offset, info.embedded_offset);
			printf("Embedded size: %u bytes\n", info.embedded_size);
			if (info.slot_payload_suspect_encrypted && !raw_key_loaded)
				printf("Signature: missing (payload appears encrypted/protected; PS1 'MC' header not visible)\n");
			else
				printf("Signature: %s\n", info.signature_present ? "present" : "missing");
		}
		else
		{
			print_ps1_signature(&info);
		}

		if (info.container)
			printf("Container: %s\n", info.container);

		if (sealedkey_override)
			sealedkey_path = sealedkey_override;
		else if (info.sealedkey_path[0] != '\0')
			sealedkey_path = info.sealedkey_path;

		if (sealedkey_path)
		{
			size_t sealedkey_size = 0;
			int sealedkey_size_known = read_file_size(sealedkey_path, &sealedkey_size);

			if (pfs_parse_sealedkey(sealedkey_path, &sk_info) && sk_info.valid)
				sealedkey_valid = 1;

			if (sealedkey_valid)
			{
				printf("Sealed key: present (pfsSKKey, 96 bytes) [%s]\n", sealedkey_path);
				printf("Keyset: %u\n", sk_info.keyset);
			}
			else if (sealedkey_override)
			{
				printf("Sealed key: invalid (expected 96 bytes + magic pfsSKKey)\n");
				if (sealedkey_size_known && raw_key_size_allowed(sealedkey_size))
					printf("Hint: This looks like a raw key blob; use --rawkey instead.\n");
			}
		}

		if (rawkey_override)
			print_raw_key_info(rawkey_override);
	}

	puts("");
	return 0;
}

static int dump_slot_with_validation(const char* vmc_path, uint32_t target_slot, const char* out_prefix, const char* rawkey_path, const raw_key_blob_t* raw_key, const char* op_label)
{
	vmc_info_t info;
	uint8_t raw_slot[PS1_RAW_SIZE];
	uint8_t cand_slot[PS1_RAW_SIZE];
	mcd_validation_t validation;
	char raw_out[1024];
	char cand_out[1024];
	int cand_built;

	if (!vmc_path || !out_prefix || !raw_key || !raw_key->valid)
		return 0;

	if (!vmc_get_info(vmc_path, &info))
	{
		fprintf(stderr, "%s: failed to parse VMC file\n", vmc_path);
		return 0;
	}

	if (info.system != VMC_SYSTEM_PS1)
	{
		fprintf(stderr, "%s: %s supports PS1 VMC files only\n", vmc_path, op_label);
		return 0;
	}

	if (info.embedded_slots > 0)
	{
		if (target_slot >= info.embedded_slots)
		{
			fprintf(stderr, "%s: slot %u out of range (0..%u)\n", vmc_path, target_slot, info.embedded_slots - 1);
			return 0;
		}

		if (!vmc_read_embedded_slot(vmc_path, target_slot, raw_slot, sizeof(raw_slot)))
		{
			fprintf(stderr, "%s: failed to read slot %u\n", vmc_path, target_slot);
			return 0;
		}
	}
	else if (info.system == VMC_SYSTEM_PS1 && info.raw_size == PS1_RAW_SIZE)
	{
		FILE* in = fopen(vmc_path, "rb");
		if (!in)
		{
			fprintf(stderr, "%s: failed to open input\n", vmc_path);
			return 0;
		}

		if (fread(raw_slot, 1, sizeof(raw_slot), in) != sizeof(raw_slot))
		{
			fclose(in);
			fprintf(stderr, "%s: failed to read raw PS1 VMC\n", vmc_path);
			return 0;
		}
		fclose(in);

		if (target_slot != 0)
		{
			fprintf(stderr, "%s: %s requested slot %u but raw PS1 VMC has only slot 0\n", vmc_path, op_label, target_slot);
			return 0;
		}
	}
	else
	{
		fprintf(stderr, "%s: %s supports PS1 raw cards and PS1HD container VMCs\n", vmc_path, op_label);
		return 0;
	}

	cand_built = build_best_transformed_slot(raw_slot, target_slot, raw_key, cand_slot);
	if (!cand_built)
		memset(cand_slot, 0, sizeof(cand_slot));

	validation = validate_mcd_buffer(cand_slot, sizeof(cand_slot), op_label, 0);
	if (cand_built && validation.verdict == MCD_VALID)
	{
		if (!write_buffer_file(out_prefix, cand_slot, sizeof(cand_slot)))
		{
			fprintf(stderr, "%s: failed to write %s\n", vmc_path, out_prefix);
			return 0;
		}

		printf("%s slot %u -> %s (%u bytes, valid .mcd)\n", op_label, target_slot, out_prefix, PS1_RAW_SIZE);
		return 1;
	}

	snprintf(raw_out, sizeof(raw_out), "%s.raw", out_prefix);
	snprintf(cand_out, sizeof(cand_out), "%s.cand", out_prefix);

	if (!write_buffer_file(raw_out, raw_slot, sizeof(raw_slot)))
	{
		fprintf(stderr, "%s: failed to write %s\n", vmc_path, raw_out);
		return 0;
	}

	if (cand_built && !write_buffer_file(cand_out, cand_slot, sizeof(cand_slot)))
	{
		fprintf(stderr, "%s: failed to write %s\n", vmc_path, cand_out);
		return 0;
	}

	fprintf(stderr,
		"%s slot %u invalid mcd header; key=%s (%zu bytes), candidate_MC=%s, raw16=",
		op_label,
		target_slot,
		rawkey_path ? rawkey_path : "<none>",
		raw_key->len,
		(cand_built && cand_slot[0] == 'M' && cand_slot[1] == 'C') ? "yes" : "no");
	print_first16_hex_to(stderr, raw_slot);
	fprintf(stderr, " cand16=");
	if (cand_built)
		print_first16_hex_to(stderr, cand_slot);
	else
		fprintf(stderr, "<none>");
	fprintf(stderr, " wrote=%s%s%s\n", raw_out, cand_built ? "," : "", cand_built ? cand_out : "");

	return 0;
}

int main(int argc, char** argv)
{
	int i;
	int failed = 0;
	int argi = 1;
	int has_slot = 0;
	int list_slots = 0;
	int fingerprint = 0;
	int has_dump_slot = 0;
	int has_decrypt_out = 0;
	uint32_t slot = 0;
	uint32_t dump_slot = 0;
	const char* dump_outfile = NULL;
	const char* decrypt_outfile = NULL;
	const char* sealedkey_override = NULL;
	const char* rawkey_override = NULL;
	const char* input_paths[argc > 0 ? (size_t) argc : 1];
	int input_count = 0;

	if (argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}

	while (argi < argc)
	{
		if (strcmp(argv[argi], "--help") == 0 || strcmp(argv[argi], "-h") == 0)
		{
			print_usage(argv[0]);
			return 0;
		}

		if (strcmp(argv[argi], "--slot") == 0)
		{
			char* end;
			unsigned long parsed;

			if (argi + 1 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			parsed = strtoul(argv[argi + 1], &end, 10);
			if (*argv[argi + 1] == '\0' || *end != '\0' || parsed > UINT32_MAX)
			{
				fprintf(stderr, "Invalid slot value: %s\n", argv[argi + 1]);
				return 1;
			}

			slot = (uint32_t) parsed;
			has_slot = 1;
			argi += 2;
			continue;
		}

		if (strcmp(argv[argi], "--dump-slot") == 0)
		{
			char* end;
			unsigned long parsed;

			if (argi + 2 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			parsed = strtoul(argv[argi + 1], &end, 10);
			if (*argv[argi + 1] == '\0' || *end != '\0' || parsed > UINT32_MAX)
			{
				fprintf(stderr, "Invalid dump slot value: %s\n", argv[argi + 1]);
				return 1;
			}

			dump_slot = (uint32_t) parsed;
			dump_outfile = argv[argi + 2];
			has_dump_slot = 1;
			argi += 3;
			continue;
		}

		if (strcmp(argv[argi], "--decrypt") == 0)
		{
			if (argi + 1 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			decrypt_outfile = argv[argi + 1];
			has_decrypt_out = 1;
			argi += 2;
			continue;
		}

		if (strcmp(argv[argi], "--list-slots") == 0)
		{
			list_slots = 1;
			argi += 1;
			continue;
		}

		if (strcmp(argv[argi], "--fingerprint") == 0)
		{
			fingerprint = 1;
			argi += 1;
			continue;
		}

		if (strcmp(argv[argi], "--sealedkey") == 0)
		{
			if (argi + 1 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			sealedkey_override = argv[argi + 1];
			argi += 2;
			continue;
		}

		if (strcmp(argv[argi], "--rawkey") == 0)
		{
			if (argi + 1 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			rawkey_override = argv[argi + 1];
			argi += 2;
			continue;
		}

		if (strncmp(argv[argi], "--", 2) == 0)
		{
			print_usage(argv[0]);
			return 1;
		}

		input_paths[input_count++] = argv[argi];
		argi += 1;
	}

	if (input_count == 0)
	{
		print_usage(argv[0]);
		return 1;
	}

	if (has_dump_slot)
	{
		vmc_info_t info;
		const char* vmc_path;
		raw_key_blob_t raw_key;
		int raw_key_loaded;

		if (input_count != 1)
		{
			fprintf(stderr, "--dump-slot accepts exactly one input VMC file\n");
			return 1;
		}

		vmc_path = input_paths[0];
		if (!vmc_get_info(vmc_path, &info) || info.embedded_slots == 0)
		{
			fprintf(stderr, "%s: --dump-slot requires a PS1HD container VMC\n", vmc_path);
			return 1;
		}

		if (dump_slot >= info.embedded_slots)
		{
			fprintf(stderr, "%s: slot %u out of range (0..%u)\n", vmc_path, dump_slot, info.embedded_slots - 1);
			return 1;
		}

		raw_key_loaded = load_raw_key(rawkey_override, &raw_key);

		if (!raw_key_loaded)
		{
			if (rawkey_override)
				fprintf(stderr, "Warning: unable to load raw key from %s; dumping raw slot bytes\n", rawkey_override);

			if (!vmc_dump_embedded_slot(vmc_path, dump_slot, dump_outfile))
			{
				fprintf(stderr, "%s: failed to dump slot %u to %s\n", vmc_path, dump_slot, dump_outfile);
				return 1;
			}

			printf("dump-slot slot %u -> %s (%u bytes, raw bytes; no valid raw-key transform available)\n", dump_slot, dump_outfile, PS1_RAW_SIZE);
		}
		else if (!dump_slot_with_validation(vmc_path, dump_slot, dump_outfile, rawkey_override, &raw_key, "dump-slot"))
		{
			return 1;
		}
	}

	if (has_decrypt_out)
	{
		raw_key_blob_t raw_key;

		if (input_count != 1)
		{
			fprintf(stderr, "--decrypt accepts exactly one input VMC file\n");
			return 1;
		}

		if (!rawkey_override)
		{
			fprintf(stderr, "--decrypt requires --rawkey PATH\n");
			return 1;
		}

		if (!load_raw_key(rawkey_override, &raw_key))
		{
			fprintf(stderr, "Failed to load raw key from %s\n", rawkey_override);
			return 1;
		}

		if (!dump_slot_with_validation(input_paths[0], has_slot ? slot : 0, decrypt_outfile, rawkey_override, &raw_key, "decrypt"))
			return 1;
	}

	for (i = 0; i < input_count; i++)
		failed |= print_vmc_info(input_paths[i], has_slot, slot, sealedkey_override, rawkey_override, list_slots, fingerprint);

	return failed ? 2 : 0;
}
