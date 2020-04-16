// SPDX-License-Identifier: GPL-2.0
/*
 * pptt.c - parsing of Processor Properties Topology Table (PPTT)
 *
 * Copyright (C) 2018, ARM
 *
 * This file implements parsing of the Processor Properties Topology Table
 * which is optionally used to describe the processor and cache topology.
 * Due to the relative pointers used throughout the table, this doesn't
 * leverage the existing subtable parsing in the kernel.
 *
 * The PPTT structure is an inverted tree, with each node potentially
 * holding one or two inverted tree data structures describing
 * the caches available at that level. Each cache structure optionally
 * contains properties describing the cache at a given level which can be
 * used to override hardware probed values.
 */
#define pr_fmt(fmt) "ACPI PPTT: " fmt

#include <linux/acpi.h>
#include <linux/cacheinfo.h>
#include <acpi/processor.h>

static struct acpi_subtable_header *fetch_pptt_subtable(struct acpi_table_header *table_hdr,
							u32 pptt_ref)
{
	struct acpi_subtable_header *entry;

	/* there isn't a subtable at reference 0 */
	if (pptt_ref < sizeof(struct acpi_subtable_header))
		return NULL;

	if (pptt_ref + sizeof(struct acpi_subtable_header) > table_hdr->length)
		return NULL;

	entry = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr, pptt_ref);

	if (entry->length == 0)
		return NULL;

	if (pptt_ref + entry->length > table_hdr->length)
		return NULL;

	return entry;
}

static struct acpi_pptt_processor *fetch_pptt_node(struct acpi_table_header *table_hdr,
						   u32 pptt_ref)
{
	return (struct acpi_pptt_processor *)fetch_pptt_subtable(table_hdr, pptt_ref);
}

static struct acpi_pptt_cache *fetch_pptt_cache(struct acpi_table_header *table_hdr,
						u32 pptt_ref)
{
	return (struct acpi_pptt_cache *)fetch_pptt_subtable(table_hdr, pptt_ref);
}

static struct acpi_subtable_header *acpi_get_pptt_resource(struct acpi_table_header *table_hdr,
							   struct acpi_pptt_processor *node,
							   int resource)
{
	u32 *ref;

	if (resource >= node->number_of_priv_resources)
		return NULL;

	ref = ACPI_ADD_PTR(u32, node, sizeof(struct acpi_pptt_processor));
	ref += resource;

	return fetch_pptt_subtable(table_hdr, *ref);
}

static inline bool acpi_pptt_match_type(int table_type, int type)
{
	return ((table_type & ACPI_PPTT_MASK_CACHE_TYPE) == type ||
		table_type & ACPI_PPTT_CACHE_TYPE_UNIFIED & type);
}

/**
 * acpi_pptt_walk_cache() - Attempt to find the requested acpi_pptt_cache
 * @table_hdr: Pointer to the head of the PPTT table
 * @local_level: passed res reflects this cache level
 * @res: cache resource in the PPTT we want to walk
 * @found: returns a pointer to the requested level if found
 * @level: the requested cache level
 * @type: the requested cache type
 *
 * Attempt to find a given cache level, while counting the max number
 * of cache levels for the cache node.
 *
 * Given a pptt resource, verify that it is a cache node, then walk
 * down each level of caches, counting how many levels are found
 * as well as checking the cache type (icache, dcache, unified). If a
 * level & type match, then we set found, and continue the search.
 * Once the entire cache branch has been walked return its max
 * depth.
 *
 * Return: The cache structure and the level we terminated with.
 */
static unsigned int acpi_pptt_walk_cache(struct acpi_table_header *table_hdr,
					 unsigned int local_level,
					 struct acpi_subtable_header *res,
					 struct acpi_pptt_cache **found,
					 unsigned int level, int type)
{
	struct acpi_pptt_cache *cache;

	if (res->type != ACPI_PPTT_TYPE_CACHE)
		return 0;

	cache = (struct acpi_pptt_cache *) res;
	while (cache) {
		local_level++;

		if (local_level == level &&
		    cache->flags & ACPI_PPTT_CACHE_TYPE_VALID &&
		    acpi_pptt_match_type(cache->attributes, type)) {
			if (*found != NULL && cache != *found)
				pr_warn("Found duplicate cache level/type unable to determine uniqueness\n");

			pr_debug("Found cache @ level %u\n", level);
			*found = cache;
			/*
			 * continue looking at this node's resource list
			 * to verify that we don't find a duplicate
			 * cache node.
			 */
		}
		cache = fetch_pptt_cache(table_hdr, cache->next_level_of_cache);
	}
	return local_level;
}

static struct acpi_pptt_cache *
acpi_find_cache_level(struct acpi_table_header *table_hdr,
		      struct acpi_pptt_processor *cpu_node,
		      unsigned int *starting_level, unsigned int level,
		      int type)
{
	struct acpi_subtable_header *res;
	unsigned int number_of_levels = *starting_level;
	int resource = 0;
	struct acpi_pptt_cache *ret = NULL;
	unsigned int local_level;

	/* walk down from processor node */
	while ((res = acpi_get_pptt_resource(table_hdr, cpu_node, resource))) {
		resource++;

		local_level = acpi_pptt_walk_cache(table_hdr, *starting_level,
						   res, &ret, level, type);
		/*
		 * we are looking for the max depth. Since its potentially
		 * possible for a given node to have resources with differing
		 * depths verify that the depth we have found is the largest.
		 */
		if (number_of_levels < local_level)
			number_of_levels = local_level;
	}
	if (number_of_levels > *starting_level)
		*starting_level = number_of_levels;

	return ret;
}

/**
 * acpi_count_levels() - Given a PPTT table, and a CPU node, count the caches
 * @table_hdr: Pointer to the head of the PPTT table
 * @cpu_node: processor node we wish to count caches for
 *
 * Given a processor node containing a processing unit, walk into it and count
 * how many levels exist solely for it, and then walk up each level until we hit
 * the root node (ignore the package level because it may be possible to have
 * caches that exist across packages). Count the number of cache levels that
 * exist at each level on the way up.
 *
 * Return: Total number of levels found.
 */
static int acpi_count_levels(struct acpi_table_header *table_hdr,
			     struct acpi_pptt_processor *cpu_node)
{
	int total_levels = 0;

	do {
		acpi_find_cache_level(table_hdr, cpu_node, &total_levels, 0, 0);
		cpu_node = fetch_pptt_node(table_hdr, cpu_node->parent);
	} while (cpu_node);

	return total_levels;
}

/**
 * acpi_pptt_leaf_node() - Given a processor node, determine if its a leaf
 * @table_hdr: Pointer to the head of the PPTT table
 * @node: passed node is checked to see if its a leaf
 *
 * Determine if the *node parameter is a leaf node by iterating the
 * PPTT table, looking for nodes which reference it.
 *
 * Return: 0 if we find a node referencing the passed node (or table error),
 * or 1 if we don't.
 */
static int acpi_pptt_leaf_node(struct acpi_table_header *table_hdr,
			       struct acpi_pptt_processor *node)
{
	struct acpi_subtable_header *entry;
	unsigned long table_end;
	u32 node_entry;
	struct acpi_pptt_processor *cpu_node;
	u32 proc_sz;

	if (table_hdr->revision > 1)
		return (node->flags & ACPI_PPTT_ACPI_LEAF_NODE);

	table_end = (unsigned long)table_hdr + table_hdr->length;
	node_entry = ACPI_PTR_DIFF(node, table_hdr);
	entry = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr,
			     sizeof(struct acpi_table_pptt));
	proc_sz = sizeof(struct acpi_pptt_processor *);

	while ((unsigned long)entry + proc_sz < table_end) {
		cpu_node = (struct acpi_pptt_processor *)entry;
		if (entry->type == ACPI_PPTT_TYPE_PROCESSOR &&
		    cpu_node->parent == node_entry)
			return 0;
		if (entry->length == 0)
			return 0;
		entry = ACPI_ADD_PTR(struct acpi_subtable_header, entry,
				     entry->length);

	}
	return 1;
}

/**
 * acpi_find_processor_node() - Given a PPTT table find the requested processor
 * @table_hdr:  Pointer to the head of the PPTT table
 * @acpi_cpu_id: CPU we are searching for
 *
 * Find the subtable entry describing the provided processor.
 * This is done by iterating the PPTT table looking for processor nodes
 * which have an acpi_processor_id that matches the acpi_cpu_id parameter
 * passed into the function. If we find a node that matches this criteria
 * we verify that its a leaf node in the topology rather than depending
 * on the valid flag, which doesn't need to be set for leaf nodes.
 *
 * Return: NULL, or the processors acpi_pptt_processor*
 */
static struct acpi_pptt_processor *acpi_find_processor_node(struct acpi_table_header *table_hdr,
							    u32 acpi_cpu_id)
{
	struct acpi_subtable_header *entry;
	unsigned long table_end;
	struct acpi_pptt_processor *cpu_node;
	u32 proc_sz;

	table_end = (unsigned long)table_hdr + table_hdr->length;
	entry = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr,
			     sizeof(struct acpi_table_pptt));
	proc_sz = sizeof(struct acpi_pptt_processor *);

	/* find the processor structure associated with this cpuid */
	while ((unsigned long)entry + proc_sz < table_end) {
		cpu_node = (struct acpi_pptt_processor *)entry;

		if (entry->length == 0) {
			pr_warn("Invalid zero length subtable\n");
			break;
		}
		if (entry->type == ACPI_PPTT_TYPE_PROCESSOR &&
		    acpi_cpu_id == cpu_node->acpi_processor_id &&
		     acpi_pptt_leaf_node(table_hdr, cpu_node)) {
			return (struct acpi_pptt_processor *)entry;
		}

		entry = ACPI_ADD_PTR(struct acpi_subtable_header, entry,
				     entry->length);
	}

	return NULL;
}


/*
 * acpi_pptt_find_cache_backwards() - Given a PPTT cache find a processor node
 * that points to it. This lets us find a cacheinfo node by fw_token, but
 * is totally broken as many processor node may point at the same PPTT
 * cache indicating different instances of the cache. (e.g. all the L1
 * caches are the same shape, but they aren't the same cache).
 * This only works if you cooked your PPTT table to look like this.
 */
struct acpi_pptt_processor *
acpi_pptt_find_cache_backwards(struct acpi_table_header *table_hdr,
			       struct acpi_pptt_cache *cache)
{
	struct acpi_pptt_processor *cpu_node;
	struct acpi_subtable_header *entry;
	struct acpi_subtable_header *res;
	unsigned long table_end;
	u32 proc_sz;
	int i;

	table_end = (unsigned long)table_hdr + table_hdr->length;
	entry = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr,
			     sizeof(struct acpi_table_pptt));
	proc_sz = sizeof(struct acpi_pptt_processor *);

	/* find the processor structure which points at  with this cpuid */
	while ((unsigned long)entry + proc_sz < table_end) {
		if (entry->length == 0) {
			pr_warn("Invalid zero length subtable\n");
			break;
		}

		cpu_node = (struct acpi_pptt_processor *)entry;
		entry = ACPI_ADD_PTR(struct acpi_subtable_header, entry,
				     entry->length);

		if (cpu_node->header.type != ACPI_PPTT_TYPE_PROCESSOR)
			continue;

		for (i = 0; i < cpu_node->number_of_priv_resources; i++) {
			res = acpi_get_pptt_resource(table_hdr, cpu_node, i);
			if (&cache->header == res)
				return cpu_node;
		}
	}

	return NULL;
}

/**
 * acpi_validate_cache_node() - Given an offset in the table, check this is
 * a cache node.
 * Used for cross-table pointers.
 *
 * Return the cache pointer for a valid cache, or NULL.
 */
struct acpi_pptt_cache *
acpi_pptt_validate_cache_node(struct acpi_table_header *table_hdr, u32 offset)
{
	struct acpi_subtable_header *entry, *cache;
	unsigned long table_end;

	if ((offset < sizeof(*table_hdr)) || (offset >= table_hdr->length))
		return NULL;

	table_end = (unsigned long)table_hdr + table_hdr->length;
	entry = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr,
			     sizeof(struct acpi_table_pptt));

	cache = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr, offset);

	/* Walk every node to check offset is on a node boundary */
	while ((unsigned long)(entry + 1) < table_end) {
		if (entry->length == 0) {
			pr_err("Invalid zero length subtable\n");
			break;
		}
		if ((entry->type == ACPI_PPTT_TYPE_CACHE) && (entry == cache))
			return (struct acpi_pptt_cache *)entry;

		entry = ACPI_ADD_PTR(struct acpi_subtable_header, entry,
				     entry->length);
	}

	return NULL;
}


static int acpi_find_cache_levels(struct acpi_table_header *table_hdr,
				  u32 acpi_cpu_id)
{
	int number_of_levels = 0;
	struct acpi_pptt_processor *cpu;

	cpu = acpi_find_processor_node(table_hdr, acpi_cpu_id);
	if (cpu)
		number_of_levels = acpi_count_levels(table_hdr, cpu);

	return number_of_levels;
}

static u8 acpi_cache_type(enum cache_type type)
{
	switch (type) {
	case CACHE_TYPE_DATA:
		pr_debug("Looking for data cache\n");
		return ACPI_PPTT_CACHE_TYPE_DATA;
	case CACHE_TYPE_INST:
		pr_debug("Looking for instruction cache\n");
		return ACPI_PPTT_CACHE_TYPE_INSTR;
	default:
	case CACHE_TYPE_UNIFIED:
		pr_debug("Looking for unified cache\n");
		/*
		 * It is important that ACPI_PPTT_CACHE_TYPE_UNIFIED
		 * contains the bit pattern that will match both
		 * ACPI unified bit patterns because we use it later
		 * to match both cases.
		 */
		return ACPI_PPTT_CACHE_TYPE_UNIFIED;
	}
}

static struct acpi_pptt_cache *acpi_find_cache_node(struct acpi_table_header *table_hdr,
						    u32 acpi_cpu_id,
						    enum cache_type type,
						    unsigned int level,
						    struct acpi_pptt_processor **node)
{
	unsigned int total_levels = 0;
	struct acpi_pptt_cache *found = NULL;
	struct acpi_pptt_processor *cpu_node;
	u8 acpi_type = acpi_cache_type(type);

	pr_debug("Looking for CPU %d's level %u cache type %d\n",
		 acpi_cpu_id, level, acpi_type);

	cpu_node = acpi_find_processor_node(table_hdr, acpi_cpu_id);

	while (cpu_node && !found) {
		found = acpi_find_cache_level(table_hdr, cpu_node,
					      &total_levels, level, acpi_type);
		*node = cpu_node;
		cpu_node = fetch_pptt_node(table_hdr, cpu_node->parent);
	}

	return found;
}

/**
 * acpi_pptt_min_physid_from_cpu_node() - Recursivly find @min_physid for all
 * leaf CPUs below @cpu_node.
 * @table_hdr:  Pointer to the head of the PPTT table
 * @cpu_node:   The point in the toplogy to start the walk
 * @min_physid: The min_physid to update with leaf CPUs.
 * @min_cpu_node: The min_cpu_node to update with leaf CPUs.
 */
void acpi_pptt_find_min_physid_cpu_node(struct acpi_table_header *table_hdr,
			struct acpi_pptt_processor *cpu_node,
			phys_cpuid_t *min_physid,
			struct acpi_pptt_processor **min_cpu_node)
{
	bool leaf = true;
	u32 acpi_processor_id;
	phys_cpuid_t cpu_node_phys_id;
	struct acpi_subtable_header *iter;
	struct acpi_pptt_processor *iter_node = NULL;
	u32 target_node = ACPI_PTR_DIFF(cpu_node, table_hdr);
	u32 proc_sz = sizeof(struct acpi_pptt_processor *);
	unsigned long table_end = (unsigned long)table_hdr + table_hdr->length;

	/*
	 * Walk the PPTT, looking for nodes that reference cpu_node
	 * as parent.
	 */
	iter = ACPI_ADD_PTR(struct acpi_subtable_header, table_hdr,
				sizeof(struct acpi_table_pptt));

	while ((unsigned long)iter + proc_sz < table_end) {
		iter_node = (struct acpi_pptt_processor *)iter;

		if (iter->type == ACPI_PPTT_TYPE_PROCESSOR &&
			iter_node->parent == target_node) {
			leaf = false;
			acpi_pptt_find_min_physid_cpu_node(table_hdr, iter_node,
						min_physid, min_cpu_node);
		}

		if (iter->length == 0)
			return;
		iter = ACPI_ADD_PTR(struct acpi_subtable_header, iter,
					iter->length);
	}

	acpi_processor_id = cpu_node->acpi_processor_id;
	cpu_node_phys_id = acpi_id_to_phys_cpuid(acpi_processor_id);
	if (!invalid_phys_cpuid(cpu_node_phys_id) &&
		*min_physid > cpu_node_phys_id &&
		leaf == true) {
		*min_physid = cpu_node_phys_id;
		*min_cpu_node = cpu_node;
	}
}

/**
 * update_cache_properties() - Update cacheinfo for the given processor
 * @this_leaf: Kernel cache info structure being updated
 * @found_cache: The PPTT node describing this cache instance
 * @cpu_node: A unique reference to describe this cache instance
 *
 * The ACPI spec implies that the fields in the cache structures are used to
 * extend and correct the information probed from the hardware. Lets only
 * set fields that we determine are VALID.
 *
 * Return: nothing. Side effect of updating the global cacheinfo
 */
static void update_cache_properties(struct cacheinfo *this_leaf,
				    struct acpi_pptt_cache *found_cache,
				    struct acpi_pptt_processor *cpu_node)
{
	this_leaf->fw_token = cpu_node;
	if (found_cache->flags & ACPI_PPTT_SIZE_PROPERTY_VALID)
		this_leaf->size = found_cache->size;
	if (found_cache->flags & ACPI_PPTT_LINE_SIZE_VALID)
		this_leaf->coherency_line_size = found_cache->line_size;
	if (found_cache->flags & ACPI_PPTT_NUMBER_OF_SETS_VALID)
		this_leaf->number_of_sets = found_cache->number_of_sets;
	if (found_cache->flags & ACPI_PPTT_ASSOCIATIVITY_VALID)
		this_leaf->ways_of_associativity = found_cache->associativity;
	if (found_cache->flags & ACPI_PPTT_WRITE_POLICY_VALID) {
		switch (found_cache->attributes & ACPI_PPTT_MASK_WRITE_POLICY) {
		case ACPI_PPTT_CACHE_POLICY_WT:
			this_leaf->attributes = CACHE_WRITE_THROUGH;
			break;
		case ACPI_PPTT_CACHE_POLICY_WB:
			this_leaf->attributes = CACHE_WRITE_BACK;
			break;
		}
	}
	if (found_cache->flags & ACPI_PPTT_ALLOCATION_TYPE_VALID) {
		switch (found_cache->attributes & ACPI_PPTT_MASK_ALLOCATION_TYPE) {
		case ACPI_PPTT_CACHE_READ_ALLOCATE:
			this_leaf->attributes |= CACHE_READ_ALLOCATE;
			break;
		case ACPI_PPTT_CACHE_WRITE_ALLOCATE:
			this_leaf->attributes |= CACHE_WRITE_ALLOCATE;
			break;
		case ACPI_PPTT_CACHE_RW_ALLOCATE:
		case ACPI_PPTT_CACHE_RW_ALLOCATE_ALT:
			this_leaf->attributes |=
				CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE;
			break;
		}
	}
	/*
	 * If cache type is NOCACHE, then the cache hasn't been specified
	 * via other mechanisms.  Update the type if a cache type has been
	 * provided.
	 *
	 * Note, we assume such caches are unified based on conventional system
	 * design and known examples.  Significant work is required elsewhere to
	 * fully support data/instruction only type caches which are only
	 * specified in PPTT.
	 */
	if (this_leaf->type == CACHE_TYPE_NOCACHE &&
	    found_cache->flags & ACPI_PPTT_CACHE_TYPE_VALID)
		this_leaf->type = CACHE_TYPE_UNIFIED;
}

static void cache_setup_acpi_cpu(struct acpi_table_header *table,
				 unsigned int cpu)
{
	struct acpi_pptt_cache *found_cache;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	struct cacheinfo *this_leaf;
	unsigned int index = 0;
	struct acpi_pptt_processor *cpu_node = NULL;

	while (index < get_cpu_cacheinfo(cpu)->num_leaves) {
		this_leaf = this_cpu_ci->info_list + index;
		found_cache = acpi_find_cache_node(table, acpi_cpu_id,
						   this_leaf->type,
						   this_leaf->level,
						   &cpu_node);
		pr_debug("found = %p %p\n", found_cache, cpu_node);
		if (found_cache)
			update_cache_properties(this_leaf,
						found_cache,
						cpu_node);

		index++;
	}
}

static bool flag_identical(struct acpi_table_header *table_hdr,
			   struct acpi_pptt_processor *cpu)
{
	struct acpi_pptt_processor *next;

	/* heterogeneous machines must use PPTT revision > 1 */
	if (table_hdr->revision < 2)
		return false;

	/* Locate the last node in the tree with IDENTICAL set */
	if (cpu->flags & ACPI_PPTT_ACPI_IDENTICAL) {
		next = fetch_pptt_node(table_hdr, cpu->parent);
		if (!(next && next->flags & ACPI_PPTT_ACPI_IDENTICAL))
			return true;
	}

	return false;
}

/* Passing level values greater than this will result in search termination */
#define PPTT_ABORT_PACKAGE 0xFF

static struct acpi_pptt_processor *acpi_find_processor_tag(struct acpi_table_header *table_hdr,
							   struct acpi_pptt_processor *cpu,
							   int level, int flag)
{
	struct acpi_pptt_processor *prev_node;

	while (cpu && level) {
		/* special case the identical flag to find last identical */
		if (flag == ACPI_PPTT_ACPI_IDENTICAL) {
			if (flag_identical(table_hdr, cpu))
				break;
		} else if (cpu->flags & flag)
			break;
		pr_debug("level %d\n", level);
		prev_node = fetch_pptt_node(table_hdr, cpu->parent);
		if (prev_node == NULL)
			break;
		cpu = prev_node;
		level--;
	}
	return cpu;
}

static void acpi_pptt_warn_missing(void)
{
	pr_warn_once("No PPTT table found, CPU and cache topology may be inaccurate\n");
}

/**
 * topology_get_acpi_cpu_tag() - Find a unique topology value for a feature
 * @table: Pointer to the head of the PPTT table
 * @cpu: Kernel logical CPU number
 * @level: A level that terminates the search
 * @flag: A flag which terminates the search
 *
 * Get a unique value given a CPU, and a topology level, that can be
 * matched to determine which cpus share common topological features
 * at that level.
 *
 * Return: Unique value, or -ENOENT if unable to locate CPU
 */
static int topology_get_acpi_cpu_tag(struct acpi_table_header *table,
				     unsigned int cpu, int level, int flag)
{
	struct acpi_pptt_processor *cpu_node;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);

	cpu_node = acpi_find_processor_node(table, acpi_cpu_id);
	if (cpu_node) {
		cpu_node = acpi_find_processor_tag(table, cpu_node,
						   level, flag);
		/*
		 * As per specification if the processor structure represents
		 * an actual processor, then ACPI processor ID must be valid.
		 * For processor containers ACPI_PPTT_ACPI_PROCESSOR_ID_VALID
		 * should be set if the UID is valid
		 */
		if (level == 0 ||
		    cpu_node->flags & ACPI_PPTT_ACPI_PROCESSOR_ID_VALID)
			return cpu_node->acpi_processor_id;
		return ACPI_PTR_DIFF(cpu_node, table);
	}
	pr_warn_once("PPTT table found, but unable to locate core %d (%d)\n",
		    cpu, acpi_cpu_id);
	return -ENOENT;
}

static int find_acpi_cpu_topology_tag(unsigned int cpu, int level, int flag)
{
	struct acpi_table_header *table;
	acpi_status status;
	int retval;

	status = acpi_get_table(ACPI_SIG_PPTT, 0, &table);
	if (ACPI_FAILURE(status)) {
		acpi_pptt_warn_missing();
		return -ENOENT;
	}
	retval = topology_get_acpi_cpu_tag(table, cpu, level, flag);
	pr_debug("Topology Setup ACPI CPU %d, level %d ret = %d\n",
		 cpu, level, retval);
	acpi_put_table(table);

	return retval;
}

/**
 * check_acpi_cpu_flag() - Determine if CPU node has a flag set
 * @cpu: Kernel logical CPU number
 * @rev: The minimum PPTT revision defining the flag
 * @flag: The flag itself
 *
 * Check the node representing a CPU for a given flag.
 *
 * Return: -ENOENT if the PPTT doesn't exist, the CPU cannot be found or
 *	   the table revision isn't new enough.
 *	   1, any passed flag set
 *	   0, flag unset
 */
static int check_acpi_cpu_flag(unsigned int cpu, int rev, u32 flag)
{
	struct acpi_table_header *table;
	acpi_status status;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	struct acpi_pptt_processor *cpu_node = NULL;
	int ret = -ENOENT;

	status = acpi_get_table(ACPI_SIG_PPTT, 0, &table);
	if (ACPI_FAILURE(status)) {
		pr_warn_once("No PPTT table found, cpu topology may be inaccurate\n");
		return ret;
	}

	if (table->revision >= rev)
		cpu_node = acpi_find_processor_node(table, acpi_cpu_id);

	if (cpu_node)
		ret = (cpu_node->flags & flag) != 0;

	acpi_put_table(table);

	return ret;
}

/**
 * acpi_find_last_cache_level() - Determines the number of cache levels for a PE
 * @cpu: Kernel logical CPU number
 *
 * Given a logical CPU number, returns the number of levels of cache represented
 * in the PPTT. Errors caused by lack of a PPTT table, or otherwise, return 0
 * indicating we didn't find any cache levels.
 *
 * Return: Cache levels visible to this core.
 */
int acpi_find_last_cache_level(unsigned int cpu)
{
	u32 acpi_cpu_id;
	struct acpi_table_header *table;
	int number_of_levels = 0;
	acpi_status status;

	pr_debug("Cache Setup find last level CPU=%d\n", cpu);

	acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	status = acpi_get_table(ACPI_SIG_PPTT, 0, &table);
	if (ACPI_FAILURE(status)) {
		acpi_pptt_warn_missing();
	} else {
		number_of_levels = acpi_find_cache_levels(table, acpi_cpu_id);
		acpi_put_table(table);
	}
	pr_debug("Cache Setup find last level level=%d\n", number_of_levels);

	return number_of_levels;
}

/**
 * cache_setup_acpi() - Override CPU cache topology with data from the PPTT
 * @cpu: Kernel logical CPU number
 *
 * Updates the global cache info provided by cpu_get_cacheinfo()
 * when there are valid properties in the acpi_pptt_cache nodes. A
 * successful parse may not result in any updates if none of the
 * cache levels have any valid flags set.  Further, a unique value is
 * associated with each known CPU cache entry. This unique value
 * can be used to determine whether caches are shared between CPUs.
 *
 * Return: -ENOENT on failure to find table, or 0 on success
 */
int cache_setup_acpi(unsigned int cpu)
{
	struct acpi_table_header *table;
	acpi_status status;

	pr_debug("Cache Setup ACPI CPU %d\n", cpu);

	status = acpi_get_table(ACPI_SIG_PPTT, 0, &table);
	if (ACPI_FAILURE(status)) {
		acpi_pptt_warn_missing();
		return -ENOENT;
	}

	cache_setup_acpi_cpu(table, cpu);
	acpi_put_table(table);

	return status;
}

/**
 * acpi_pptt_cpu_is_thread() - Determine if CPU is a thread
 * @cpu: Kernel logical CPU number
 *
 * Return: 1, a thread
 *         0, not a thread
 *         -ENOENT ,if the PPTT doesn't exist, the CPU cannot be found or
 *         the table revision isn't new enough.
 */
int acpi_pptt_cpu_is_thread(unsigned int cpu)
{
	return check_acpi_cpu_flag(cpu, 2, ACPI_PPTT_ACPI_PROCESSOR_IS_THREAD);
}

/**
 * find_acpi_cpu_topology() - Determine a unique topology value for a given CPU
 * @cpu: Kernel logical CPU number
 * @level: The topological level for which we would like a unique ID
 *
 * Determine a topology unique ID for each thread/core/cluster/mc_grouping
 * /socket/etc. This ID can then be used to group peers, which will have
 * matching ids.
 *
 * The search terminates when either the requested level is found or
 * we reach a root node. Levels beyond the termination point will return the
 * same unique ID. The unique id for level 0 is the acpi processor id. All
 * other levels beyond this use a generated value to uniquely identify
 * a topological feature.
 *
 * Return: -ENOENT if the PPTT doesn't exist, or the CPU cannot be found.
 * Otherwise returns a value which represents a unique topological feature.
 */
int find_acpi_cpu_topology(unsigned int cpu, int level)
{
	return find_acpi_cpu_topology_tag(cpu, level, 0);
}

/**
 * find_acpi_cpu_cache_topology() - Determine a unique cache topology value
 * @cpu: Kernel logical CPU number
 * @level: The cache level for which we would like a unique ID
 *
 * Determine a unique ID for each unified cache in the system
 *
 * Return: -ENOENT if the PPTT doesn't exist, or the CPU cannot be found.
 * Otherwise returns a value which represents a unique topological feature.
 */
int find_acpi_cpu_cache_topology(unsigned int cpu, int level)
{
	struct acpi_table_header *table;
	struct acpi_pptt_cache *found_cache;
	acpi_status status;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	struct acpi_pptt_processor *cpu_node = NULL;
	int ret = -1;

	status = acpi_get_table(ACPI_SIG_PPTT, 0, &table);
	if (ACPI_FAILURE(status)) {
		acpi_pptt_warn_missing();
		return -ENOENT;
	}

	found_cache = acpi_find_cache_node(table, acpi_cpu_id,
					   CACHE_TYPE_UNIFIED,
					   level,
					   &cpu_node);
	if (found_cache)
		ret = ACPI_PTR_DIFF(cpu_node, table);

	acpi_put_table(table);

	return ret;
}


/**
 * find_acpi_cpu_topology_package() - Determine a unique CPU package value
 * @cpu: Kernel logical CPU number
 *
 * Determine a topology unique package ID for the given CPU.
 * This ID can then be used to group peers, which will have matching ids.
 *
 * The search terminates when either a level is found with the PHYSICAL_PACKAGE
 * flag set or we reach a root node.
 *
 * Return: -ENOENT if the PPTT doesn't exist, or the CPU cannot be found.
 * Otherwise returns a value which represents the package for this CPU.
 */
int find_acpi_cpu_topology_package(unsigned int cpu)
{
	return find_acpi_cpu_topology_tag(cpu, PPTT_ABORT_PACKAGE,
					  ACPI_PPTT_PHYSICAL_PACKAGE);
}

/**
 * find_acpi_cpu_topology_hetero_id() - Get a core architecture tag
 * @cpu: Kernel logical CPU number
 *
 * Determine a unique heterogeneous tag for the given CPU. CPUs with the same
 * implementation should have matching tags.
 *
 * The returned tag can be used to group peers with identical implementation.
 *
 * The search terminates when a level is found with the identical implementation
 * flag set or we reach a root node.
 *
 * Due to limitations in the PPTT data structure, there may be rare situations
 * where two cores in a heterogeneous machine may be identical, but won't have
 * the same tag.
 *
 * Return: -ENOENT if the PPTT doesn't exist, or the CPU cannot be found.
 * Otherwise returns a value which represents a group of identical cores
 * similar to this CPU.
 */
int find_acpi_cpu_topology_hetero_id(unsigned int cpu)
{
	return find_acpi_cpu_topology_tag(cpu, PPTT_ABORT_PACKAGE,
					  ACPI_PPTT_ACPI_IDENTICAL);
}
