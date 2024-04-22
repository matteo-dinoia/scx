/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_simple_mine.bpf.skel.h"

#define STAT_SIZE 4

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-p]\n"
"\n"
"  -p            Switch only tasks on SCHED_EXT policy intead of all\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct scx_simple_mine *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[STAT_SIZE][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * STAT_SIZE);

	for (idx = 0; idx < STAT_SIZE; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++) //it is for single cpu and then added
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_simple_mine *skel;
	struct bpf_link *link;
	__u32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_simple_mine__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	while ((opt = getopt(argc, argv, "ph")) != -1) {
		switch (opt) {
		case 'p':
			skel->rodata->switch_partial = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, simple_mine_ops, scx_simple_mine, uei);
	link = SCX_OPS_ATTACH(skel, simple_mine_ops);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[STAT_SIZE];

		read_stats(skel, stats);
		printf("local=%llu global=%llu little=%llu big=%llu\n", stats[0], stats[1], stats[2], stats[3]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_simple_mine__destroy(skel);
	return 0;
}
