#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "vmc_info.h"

#define SLOT_SUMMARY_LIMIT 10
#define PS1HD_HEADER_SIZE 0x8000
#define PS1_RAW_SIZE 0x20000

static void print_usage(const char* argv0)
{
	fprintf(stderr, "Usage: %s [--slot N] [--sealedkey PATH] <memory-card.vmc> [more...]\n", argv0);
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

static int print_slot_summary(const char* path, uint32_t slots, int encrypted)
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
		vmc_info_t slot_info;

		if (!vmc_get_info_slot(path, &slot_info, i))
		{
			printf("slot %u: <read error>\n", i);
			continue;
		}

		if (!slot_info.signature_present && encrypted)
			printf("slot %u: signature missing (high entropy)\n", i);
		else
			printf("slot %u: signature %s\n", i, slot_info.signature_present ? "present" : "missing");
	}

	if (slots > limit)
		printf("...\n");

	return 0;
}

static int print_vmc_info(const char* path, int has_slot, uint32_t slot, const char* sealedkey_override)
{
	vmc_info_t info;
	pfs_sealedkey_info_t sk_info;
	int sealedkey_valid = 0;
	const char* sealedkey_path = NULL;

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

		if (!has_slot && info.embedded_slots > 0)
			print_slot_summary(path, info.embedded_slots, info.slot_payload_suspect_encrypted);

		if (info.embedded_slots > 0)
		{
			printf("Embedded slot: %u / %u\n", info.embedded_slot, info.embedded_slots - 1);
			printf("Embedded offset: %" PRIu64 " (0x%" PRIx64 ")\n", info.embedded_offset, info.embedded_offset);
			printf("Embedded size: %u bytes\n", info.embedded_size);
			if (info.slot_payload_suspect_encrypted)
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
			}
		}
	}

	puts("");
	return 0;
}

int main(int argc, char** argv)
{
	int i;
	int failed = 0;
	int argi = 1;
	int has_slot = 0;
	uint32_t slot = 0;
	const char* sealedkey_override = NULL;

	if (argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}

	while (argi < argc)
	{
		if (strcmp(argv[argi], "--slot") == 0)
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
				fprintf(stderr, "Invalid slot value: %s\n", argv[argi + 1]);
				return 1;
			}

			slot = (uint32_t) parsed;
			has_slot = 1;
			argi += 2;
			continue;
		}

		if (strcmp(argv[argi], "--sealedkey") == 0)
		{
			if (argi + 2 >= argc)
			{
				print_usage(argv[0]);
				return 1;
			}

			sealedkey_override = argv[argi + 1];
			argi += 2;
			continue;
		}

		if (strncmp(argv[argi], "--", 2) == 0)
		{
			print_usage(argv[0]);
			return 1;
		}

		break;
	}

	if (argi >= argc)
	{
		print_usage(argv[0]);
		return 1;
	}

	for (i = argi; i < argc; i++)
		failed |= print_vmc_info(argv[i], has_slot, slot, sealedkey_override);

	return failed ? 2 : 0;
}
