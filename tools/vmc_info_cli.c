#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "vmc_info.h"

static void print_usage(const char* argv0)
{
	fprintf(stderr, "Usage: %s <memory-card.vmc> [more.vmc ...]\n", argv0);
}

static int print_vmc_info(const char* path)
{
	vmc_info_t info;

	if (!vmc_get_info(path, &info))
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
		switch (info.ps1_signature)
		{
			case VMC_PS1_SIGNATURE_PRESENT:
				printf("Signature: MC\n");
				break;
			case VMC_PS1_SIGNATURE_MISSING_BLANK:
				printf("Signature: missing (treating as unformatted/blank PS1 raw card)\n");
				break;
			case VMC_PS1_SIGNATURE_MISSING_UNKNOWN:
				printf("Signature: missing (treating as PS1 raw card, possibly unformatted)\n");
				break;
			default:
				break;
		}
	}

	puts("");
	return 0;
}

int main(int argc, char** argv)
{
	int i;
	int failed = 0;

	if (argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}

	for (i = 1; i < argc; i++)
		failed |= print_vmc_info(argv[i]);

	return failed ? 2 : 0;
}
