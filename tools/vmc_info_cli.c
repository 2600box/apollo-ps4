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
	fprintf(stderr, "Usage: %s [--slot N] [--list-slots] [--fingerprint] [--verbose] [--dump-slot N OUTFILE] [--decrypt OUTFILE] [--sealedkey PATH] [--rawkey PATH|--rawkey-hex HEX] <memory-card.vmc> [more...]\n", argv0);
	fprintf(stderr, "  --slot N            Target embedded slot N for slot-dependent operations (including --decrypt).\n");
	fprintf(stderr, "  --dump-slot N FILE  Dump embedded slot N; writes FILE only when valid .mcd, else FILE.raw/FILE.cand.\n");
	fprintf(stderr, "  --decrypt FILE      Decrypt targeted slot (--slot, default 0) to FILE when valid .mcd, else FILE.raw/FILE.cand.\n");
	fprintf(stderr, "  --rawkey-hex HEX    Raw key bytes as hex (16/32/48 bytes). Accepts spaces/newlines/0x prefixes.\n");
	fprintf(stderr, "  --verbose           Print decrypt-path diagnostics and validation failure reasons.\n");
}

static int g_verbose = 0;

static uint64_t fnv1a64(const uint8_t* data, size_t len);
static int buffer_looks_high_entropy(const uint8_t* data, size_t len);
static int slot_has_signature(const uint8_t* slot_data);
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
	int not_all_zero;
	int not_all_ff;
	const char* fail_reason;
} mcd_validation_t;

static const size_t g_raw_key_sizes[] = {16, 32, 48};

static int dir_frames_look_plausible(const uint8_t* slot_data);

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

static int parse_hex_nibble(char c, uint8_t* out)
{
	if (!out)
		return 0;

	if (c >= '0' && c <= '9')
	{
		*out = (uint8_t) (c - '0');
		return 1;
	}

	if (c >= 'a' && c <= 'f')
	{
		*out = (uint8_t) (10 + (c - 'a'));
		return 1;
	}

	if (c >= 'A' && c <= 'F')
	{
		*out = (uint8_t) (10 + (c - 'A'));
		return 1;
	}

	return 0;
}

static int load_raw_key_hex(const char* rawkey_hex, raw_key_blob_t* out)
{
	uint8_t hi = 0;
	int have_hi = 0;
	size_t i;

	if (!out)
		return 0;

	memset(out, 0, sizeof(*out));
	if (!rawkey_hex)
		return 0;

	for (i = 0; rawkey_hex[i] != '\0'; i++)
	{
		uint8_t nibble;
		char ch = rawkey_hex[i];

		if (isspace((unsigned char) ch))
			continue;

		if (ch == '0' && (rawkey_hex[i + 1] == 'x' || rawkey_hex[i + 1] == 'X'))
		{
			i++;
			continue;
		}

		if (!parse_hex_nibble(ch, &nibble))
			return 0;

		if (!have_hi)
		{
			hi = nibble;
			have_hi = 1;
			continue;
		}

		if (out->len >= sizeof(out->data))
			return 0;

		out->data[out->len++] = (uint8_t) ((hi << 4) | nibble);
		have_hi = 0;
	}

	if (have_hi || !raw_key_size_allowed(out->len))
		return 0;

	out->valid = 1;
	return 1;
}

static int decrypt_slot_xts(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key, size_t key_len, uint64_t sector_base, int tweak_be, size_t data_unit)
{
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* cipher = NULL;
	uint8_t iv[16];
	int out_len;
	size_t off;

	if (!in || !out || !key || data_unit == 0 || len % data_unit != 0)
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

	for (off = 0; off < len; off += data_unit)
	{
		uint64_t sector = sector_base + (off / data_unit);
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

		if (EVP_DecryptUpdate(ctx, out + off, &out_len, in + off, (int) data_unit) != 1 || out_len != (int) data_unit)
		{
			EVP_CIPHER_CTX_free(ctx);
			return 0;
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

typedef struct decrypt_path {
	const char* method;
	size_t data_unit;
	uint64_t sector_base;
	int tweak_be;
	char key_fp16[17];
} decrypt_path_t;

static void key_fingerprint16_hex(const uint8_t* key, size_t len, char out[17])
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	int i;

	if (!out)
		return;

	out[0] = '\0';
	if (!key || len == 0)
		return;

	if (EVP_Digest(key, len, digest, &dlen, EVP_sha256(), NULL) != 1 || dlen < 8)
		return;

	for (i = 0; i < 8; i++)
		snprintf(out + (i * 2), 3, "%02x", digest[i]);
}

static int build_best_transformed_slot(const uint8_t* slot_data, uint32_t slot_index, const raw_key_blob_t* raw_key, uint8_t* best_candidate, decrypt_path_t* best_path)
{
	const size_t data_unit = 512;
	const uint64_t sector_base = ((uint64_t) PS1HD_HEADER_SIZE + ((uint64_t) slot_index * (uint64_t) PS1_RAW_SIZE)) / data_unit;
	const int tweak_be = 0;

	if (!slot_data || !raw_key || !raw_key->valid || !best_candidate)
		return 0;

	if (raw_key->len != 32)
		return 0;

	if (!decrypt_slot_xts(slot_data, best_candidate, PS1_RAW_SIZE, raw_key->data, raw_key->len, sector_base, tweak_be, data_unit))
		return 0;

	if (best_path)
	{
		best_path->method = "ps1hd-fixed";
		best_path->data_unit = data_unit;
		best_path->sector_base = sector_base;
		best_path->tweak_be = tweak_be;
		key_fingerprint16_hex(raw_key->data, raw_key->len, best_path->key_fp16);
	}

	return 1;
}

static int maybe_transform_slot_with_raw_key(uint8_t* slot_data, uint32_t slot_index, const raw_key_blob_t* raw_key)
{
	uint8_t best_candidate[PS1_RAW_SIZE];
	decrypt_path_t path;

	if (!slot_data || !raw_key || !raw_key->valid)
		return 0;

	if (!build_best_transformed_slot(slot_data, slot_index, raw_key, best_candidate, &path))
		return 0;

	memcpy(slot_data, best_candidate, sizeof(best_candidate));
	return 1;
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
	size_t i;
	int all_zero = 1;
	int all_ff = 1;

	memset(&out, 0, sizeof(out));
	out.fail_reason = "unknown";
	if (!data || len != PS1_RAW_SIZE)
	{
		out.fail_reason = "invalid size";
		return out;
	}

	for (i = 0; i < len; i++)
	{
		if (data[i] != 0x00)
			all_zero = 0;
		if (data[i] != 0xFF)
			all_ff = 0;
		if (!all_zero && !all_ff)
			break;
	}

	out.not_all_zero = !all_zero;
	out.not_all_ff = !all_ff;
	out.begins_with_mc = (data[0] == 'M' && data[1] == 'C');
	out.entropy_4k = estimate_shannon_entropy(data, 4096);
	out.plausible_dir_flags = dir_frames_look_plausible(data);

	if (!out.not_all_zero)
		out.fail_reason = "all bytes are 0x00";
	else if (!out.not_all_ff)
		out.fail_reason = "all bytes are 0xFF";
	else if (!out.begins_with_mc)
		out.fail_reason = "missing MC header";
	else if (!out.plausible_dir_flags)
		out.fail_reason = "directory flags implausible";
	else if (out.entropy_4k > 7.6)
		out.fail_reason = "first 4KiB looks encrypted/high-entropy";
	else
	{
		out.verdict = MCD_VALID;
		out.fail_reason = NULL;
	}

	if (verbose)
	{
		printf("MCD check (%s):\n", label ? label : "buffer");
		printf("  first16: ");
		print_first16_hex(data);
		printf("\n");
		printf("  begins_with_MC: %s\n", out.begins_with_mc ? "yes" : "no");
		printf("  entropy(first4k): %.3f bits/byte (%s)\n", out.entropy_4k, out.entropy_4k > 7.6 ? "high" : "normal");
		printf("  plausible_directory_flags: %s\n", out.plausible_dir_flags ? "yes" : "no");
		printf("  not_all_zero: %s\n", out.not_all_zero ? "yes" : "no");
		printf("  not_all_ff: %s\n", out.not_all_ff ? "yes" : "no");
		printf("  verdict: %s\n", out.verdict == MCD_VALID ? "VALID_MCD" : "NOT_MCD");
		if (out.fail_reason)
			printf("  fail_reason: %s\n", out.fail_reason);
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

static int print_vmc_info(const char* path, int has_slot, uint32_t slot, const char* sealedkey_override, const char* rawkey_override, const char* rawkey_hex_override, int explicit_list_slots, int fingerprint)
{
	vmc_info_t info;
	pfs_sealedkey_info_t sk_info;
	raw_key_blob_t raw_key;
	int sealedkey_valid = 0;
	const char* sealedkey_path = NULL;
	int raw_key_loaded = 0;

	raw_key_loaded = load_raw_key(rawkey_override, &raw_key);
	if (!raw_key_loaded)
		raw_key_loaded = load_raw_key_hex(rawkey_hex_override, &raw_key);

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
		else if (rawkey_hex_override)
			printf("Raw key: present (%zu bytes) [inline hex]\n", raw_key.len);
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
	decrypt_path_t best_path;
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

	memset(&best_path, 0, sizeof(best_path));
	cand_built = build_best_transformed_slot(raw_slot, target_slot, raw_key, cand_slot, &best_path);
	if (!cand_built)
		memset(cand_slot, 0, sizeof(cand_slot));

	if (g_verbose && cand_built)
	{
		printf("Decrypt path (%s): method=%s key_fp=%s data_unit=%zu sector_base=%" PRIu64 " tweak_endian=%s\n",
			op_label,
			best_path.method ? best_path.method : "unknown",
			best_path.key_fp16[0] ? best_path.key_fp16 : "n/a",
			best_path.data_unit,
			best_path.sector_base,
			best_path.tweak_be ? "be64" : "le64");
	}

	validation = validate_mcd_buffer(cand_slot, sizeof(cand_slot), op_label, g_verbose);
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
		"%s slot %u invalid mcd header; key=%s (%zu bytes), candidate_MC=%s, reason=%s, raw16=",
		op_label,
		target_slot,
		rawkey_path ? rawkey_path : "<none>",
		raw_key->len,
		(cand_built && cand_slot[0] == 'M' && cand_slot[1] == 'C') ? "yes" : "no",
		validation.fail_reason ? validation.fail_reason : "unknown");
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
	const char* rawkey_hex_override = NULL;
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

		if (strcmp(argv[argi], "--verbose") == 0 || strcmp(argv[argi], "--debug-decrypt") == 0)
		{
			g_verbose = 1;
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

		if (strcmp(argv[argi], "--rawkey-hex") == 0)
		{
			if (argi + 1 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			rawkey_hex_override = argv[argi + 1];
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
			raw_key_loaded = load_raw_key_hex(rawkey_hex_override, &raw_key);

		if (!raw_key_loaded)
		{
			if (rawkey_override || rawkey_hex_override)
				fprintf(stderr, "Warning: unable to load raw key (%s%s%s); dumping raw slot bytes\n", rawkey_override ? rawkey_override : "", (rawkey_override && rawkey_hex_override) ? " / " : "", rawkey_hex_override ? "inline hex" : "");

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

		if (!rawkey_override && !rawkey_hex_override)
		{
			fprintf(stderr, "--decrypt requires --rawkey PATH or --rawkey-hex HEX\n");
			return 1;
		}

		if (!load_raw_key(rawkey_override, &raw_key) && !load_raw_key_hex(rawkey_hex_override, &raw_key))
		{
			fprintf(stderr, "Failed to load raw key\n");
			return 1;
		}

		if (!dump_slot_with_validation(input_paths[0], has_slot ? slot : 0, decrypt_outfile, rawkey_override ? rawkey_override : "inline hex", &raw_key, "decrypt"))
			return 1;
	}

	for (i = 0; i < input_count; i++)
		failed |= print_vmc_info(input_paths[i], has_slot, slot, sealedkey_override, rawkey_override, rawkey_hex_override, list_slots, fingerprint);

	return failed ? 2 : 0;
}
