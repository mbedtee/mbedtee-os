// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Host tool to generate symbols table for backtrace
 * table will be linked into .rodata section later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>
#include <errno.h>

#define APP_NAME	"ksymtrace"
#define VERSION		"1.0"

static struct option long_options[] = {
	{"map",				required_argument,	NULL, 'm'},
	{"out",				required_argument,	NULL, 'o'},
	{"help",			no_argument,		NULL, 'h'},
	{0, 0, NULL, 0}
};

static void print_usage(void)
{
	fprintf(stdout, "\tVersion: %s\n", VERSION);
	fprintf(stdout, "\t--map : specify the map file (nm -n). (INPUT)\n");
	fprintf(stdout, "\t--out : specify the output file path. (OUTPUT)\n");
	fprintf(stdout, "\t--help : this help information.\n");
	fprintf(stdout, "Ex:\t ==> (./%s --map xxx.map --out xxx.c\n", APP_NAME);
}

#define SYMBOL_NUM_MAX	(5000)
#define SYMBOL_NAME_LEN  (128)

int main(int argc, char *argv[])
{
	int option_index = 0;
	int i = 0, idx = 0;
	int ret = -1, opt = -1;
	char *mappath = NULL;
	char *outpath = NULL;
	char *sget = NULL;
	struct timeval ts, te;
	FILE *in = NULL;
	FILE *out = NULL;

	char *name_array = NULL;
	unsigned long *addr_array = NULL;
	unsigned int *offset_array = NULL;
	unsigned long addr = 0, multiple = 1;
	unsigned long offset = 0, namel = 0;
	char name[512] = {0}, lbuf[1024] = {0}, type = 0;

	if ((argc == 2) && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		print_usage();
		exit(0);
	} else if (argc >= 5) {
		while ((opt = getopt_long_only(argc, argv, "m:o:h",
			long_options, &option_index)) != -1) {
			switch (opt) {
			case 'm':
				mappath = optarg;
				break;

			case 'o':
				outpath = optarg;
				break;

			case 'h': /* help information */
				print_usage();
				exit(0);

			default:
				print_usage();
				exit(ret);
			}
		}
	} else {
		print_usage();
		exit(ret);
	}

	gettimeofday(&ts, NULL);

	/* symbols name array */
	name_array = calloc(SYMBOL_NUM_MAX, SYMBOL_NAME_LEN);
	if (name_array == NULL) {
		fprintf(stderr, "out of memory\n");
		return -ENOMEM;
	}

	/* symbol run-address in the .map file */
	addr_array = calloc(SYMBOL_NUM_MAX, sizeof(unsigned long));
	if (addr_array == NULL) {
		fprintf(stderr, "out of memory\n");
		ret = -ENOMEM;
		goto out;
	}

	/* symbol name offset within the 'name_array' */
	offset_array = calloc(SYMBOL_NUM_MAX, sizeof(unsigned int));
	if (offset_array == NULL) {
		fprintf(stderr, "out of memory\n");
		ret = -ENOMEM;
		goto out;
	}

	in = fopen(mappath, "r");
	if (in == NULL) {
		fprintf(stderr, "error open map file %s\n", mappath);
		goto out;
	}
	out = fopen(outpath, "w+");
	if (out == NULL) {
		fprintf(stderr, "error open output file %s\n", outpath);
		goto out;
	}

	while ((sget = fgets(lbuf, sizeof(lbuf), in)) != NULL) {
		if (lbuf[0] == ' ')
			continue;

		namel = sscanf(lbuf, "%lx %c %511s\n", &addr, &type, name);

		/* only handle the .text symbols */
		if (type != 'T' && type != 't')
			continue;

		if (idx && ((idx % SYMBOL_NUM_MAX) == 0)) {
			multiple++;
			addr_array = realloc(addr_array, SYMBOL_NUM_MAX *
				sizeof(unsigned long) * multiple);
			offset_array = realloc(offset_array, SYMBOL_NUM_MAX *
				sizeof(unsigned int) * multiple);
			name_array = realloc(name_array, SYMBOL_NUM_MAX *
				SYMBOL_NAME_LEN * multiple);
			if (addr_array == NULL || offset_array == NULL ||
				name_array == NULL) {
				fprintf(stderr, "out of memory\n");
				ret = -ENOMEM;
				goto out;
			}
		}

		namel = strlen(name);
		if (namel >= SYMBOL_NAME_LEN) {
			fprintf(stderr, "symbol %s name too long (exceed %d)\n",
					name, SYMBOL_NAME_LEN);
			ret = -ENAMETOOLONG;
			goto out;
		}

		addr_array[idx] = addr;
		offset_array[idx] = offset;
		memcpy(name_array + offset, name, namel + 1);
		offset += namel + 1;
		idx++;
	}

	fprintf(out, "const unsigned int ksymnum = %u;\n", idx);

	/* output the run-address */
	fprintf(out, "const unsigned long ksymaddr[%u] = {\n", idx);
	for (i = 0; i < idx; i++) {
		/* trim the leading 0xffffffff for 32bit target */
		if (addr_array[i] > 0xffffffff00000000ul)
			fprintf(out, "0x%08x, ", (int)addr_array[i]);
		else
			fprintf(out, "0x%lx, ", addr_array[i]);
		if (((i + 1) & 7) == 0)
			fprintf(out, "\n");
	}
	fprintf(out, "};\n");

	/* output the offsets in name_array */
	fprintf(out, "const unsigned int ksymoffset[%u] = {\n", idx);
	for (i = 0; i < idx; i++) {
		fprintf(out, "%u, ", offset_array[i]);
		if (((i + 1) & 7) == 0)
			fprintf(out, "\n");
	}
	fprintf(out, "};\n");

	/* output the symbols' name */
	fprintf(out, "const char ksymname[%lu] = {\n", offset);
	for (i = 0; i < offset; i++) {
		fprintf(out, "0x%02x, ", name_array[i]);
		if (((i + 1) & 7) == 0)
			fprintf(out, "\n");
	}
	fprintf(out, "};\n");

	ret = 0;

out:
	gettimeofday(&te, NULL);
	/* fprintf(stdout, "Elapsed time: %ld us\n",
	 *		(1000000 * (te.tv_sec - ts.tv_sec) +
	 *		te.tv_usec - ts.tv_usec));
	 */
	free(name_array);
	free(addr_array);
	free(offset_array);
	fclose(in);
	fclose(out);
	return ret;
}
