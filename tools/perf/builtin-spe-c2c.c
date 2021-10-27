// SPDX-License-Identifier: GPL-2.0
/*
 * This is for ARM SPE c2c, such as intel c2c.
 */
#include <linux/kernel.h>
#include <string.h>
#include "util.h"
#include "debug.h"
#include "builtin.h"
#include <subcmd/parse-options.h>

static const struct option spe_c2c_options[] = {
	OPT_END()
};

static const char * const spe_c2c_usage[] = {
	"perf spe-c2c {record|report}",
	NULL
};

static int perf_spe_c2c__record(int argc, const char **argv)
{
	int rec_argc, i = 0, j;
	const char **rec_argv;
	int ret;

	rec_argc = argc + 5; /* max number of arguments */
	rec_argv = calloc(rec_argc + 1, sizeof(char *));
	if (!rec_argv)
		return -1;

	rec_argv[i++] = argv[0];
	rec_argv[i++] = "-e";
	rec_argv[i++] = "arm_spe_0/ts_enable=1,"
			"pct_enable=1,pa_enable=1,load_filter=1,"
			"jitter=1,store_filter=1,min_latency=0/";

	for (j = 1; j < argc; j++)
		rec_argv[i++] = argv[j];

	ret = cmd_record(i, rec_argv);
	free(rec_argv);
	return ret;
}

int cmd_spe_c2c(int argc, const char **argv)
{
	argc = parse_options(argc, argv, spe_c2c_options, spe_c2c_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (!argc)
		usage_with_options(spe_c2c_usage, spe_c2c_options);

	if (!strncmp(argv[0], "rec", 3))
		return perf_spe_c2c__record(argc, argv);
	else {
		if (!strncmp(argv[0], "rep", 3))
			return perf_c2c__report(argc, argv);
		usage_with_options(spe_c2c_usage, spe_c2c_options);
	}

	return 0;
}
