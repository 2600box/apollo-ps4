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
	fprintf(stderr, "Usage: %s [--slot N] <memory-card.vmc> [more.vmc ...]\n", argv0);
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
		default:
			break;
	}
}

static int print_slot_summary(const char* path, uint32_t slots)
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

		printf("slot %u: signature %s\n", i, slot_info.signature_present ? "present" : "missing");
	}

	if (slots > limit)
		printf("...\n");

	return 0;
}

static int print_vmc_info(const char* path, int has_slot, uint32_t slot)
{
	vmc_info_t info;

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
			print_slot_summary(path, info.embedded_slots);

		if (info.embedded_slots > 0)
		{
			printf("Embedded slot: %u / %u\n", info.embedded_slot, info.embedded_slots - 1);
			printf("Embedded offset: %" PRIu64 " (0x%" PRIx64 ")\n", info.embedded_offset, info.embedded_offset);
			printf("Embedded size: %u bytes\n", info.embedded_size);
			printf("Signature: %s\n", info.signature_present ? "present" : "missing");
		}
		else
		{
			print_ps1_signature(&info);
		}

		if (info.container)
			printf("Container: %s\n", info.container);
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

	if (argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}

	if (argi < argc && strcmp(argv[argi], "--slot") == 0)
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
	}

	if (argi >= argc)
	{
		print_usage(argv[0]);
		return 1;
	}

	for (i = argi; i < argc; i++)
		failed |= print_vmc_info(argv[i], has_slot, slot);

	return failed ? 2 : 0;
}
