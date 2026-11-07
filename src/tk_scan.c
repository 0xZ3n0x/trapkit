/*
 * tk_scan.c - streaming masked pattern search.
 *
 * One pass over the image's executable mappings tests all patterns at once.
 * A pattern's meaning lives with its owner; this engine knows nothing but
 * how to stream memory and match masked byte patterns.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "tk_internal.h"

static bool pattern_matches_at(const u8* data, const struct tk_pattern* pattern)
{
    size_t i;

    for (i = 0; i < pattern->length; i++)
    {
        if ((data[i] & pattern->mask[i]) != pattern->bytes[i])
        {
            return false;
        }
    }
    return true;
}

/*
 * Test every still-unmatched pattern against one buffered chunk.
 *
 * Every pattern this module uses pins its first byte, so the common case is
 * a memchr sweep for that byte and a full compare only on the rare hit.
 * memchr is word-at-a-time, which is what keeps a whole-.text scan fast
 * enough to arm before the game finishes booting.  A pattern that wildcards
 * its first byte falls back to comparing at every offset.
 */
static unsigned int search_chunk(const u8* chunk, size_t chunk_length, unsigned long chunk_address,
                                 const struct tk_pattern* patterns, unsigned int pattern_count,
                                 struct tk_scan_result* results)
{
    unsigned int newly_matched = 0;
    unsigned int i;

    for (i = 0; i < pattern_count; i++)
    {
        const struct tk_pattern* pattern = &patterns[i];
        size_t offset = 0;

        if (results[i].found || pattern->length > chunk_length)
        {
            continue;
        }

        while (offset + pattern->length <= chunk_length)
        {
            size_t last_start = chunk_length - pattern->length;
            const u8* candidate;
            unsigned long candidate_va;

            if (pattern->mask[0] == 0xFF)
            {
                candidate = memchr(chunk + offset, pattern->bytes[0], last_start - offset + 1);
                if (!candidate)
                {
                    break;
                }
            }
            else
            {
                candidate = chunk + offset;
            }

            candidate_va = chunk_address + (unsigned long)(candidate - chunk);

            /* The bytes fit; verify() (when present) decides whether this is
             * really the site, and a rejection just resumes the search one
             * byte along. */
            if (pattern_matches_at(candidate, pattern) &&
                (!pattern->verify || pattern->verify(candidate, candidate_va, pattern->context)))
            {
                results[i].found = true;
                results[i].address = candidate_va;
                newly_matched++;
                break;
            }
            offset = (size_t)(candidate - chunk) + 1;
        }
    }
    return newly_matched;
}

/*
 * Scan one contiguous range.  Returns the number of patterns matched here.
 *
 * Reads are chunked and overlap by longest_pattern - 1 bytes so a match that
 * straddles a chunk boundary is still seen.  A failed or short read means the
 * range has a hole in it (mapped but not resident, or torn down underneath
 * us); scanning resumes at the next page boundary rather than giving up.
 */
static unsigned int scan_one_range(struct task_struct* task, const struct tk_address_range* range,
                                   const struct tk_pattern* patterns, unsigned int pattern_count,
                                   struct tk_scan_result* results, u8* buffer, size_t buffer_size,
                                   size_t longest_pattern, unsigned int remaining)
{
    unsigned long cursor = range->start;
    unsigned int matched = 0;

    while (cursor + longest_pattern <= range->end)
    {
        size_t wanted = min_t(unsigned long, buffer_size, range->end - cursor);
        unsigned long resume;
        int got;

        cond_resched();

        got = tk_read_remote(task, cursor, buffer, wanted);

        /* Too little to hold even the longest pattern: skip the hole. */
        if (got < (int)longest_pattern)
        {
            resume = PAGE_ALIGN(cursor + (got > 0 ? (unsigned long)got : 0UL) + 1);
            if (resume <= cursor)
            {
                break;
            }
            cursor = resume;
            continue;
        }

        matched += search_chunk(buffer, (size_t)got, cursor, patterns, pattern_count, results);
        if (matched >= remaining)
        {
            break;
        }

        /* Short read: the rest of this chunk is unmapped, resume past it. */
        if ((size_t)got < wanted)
        {
            resume = PAGE_ALIGN(cursor + (unsigned long)got + 1);
            if (resume <= cursor)
            {
                break;
            }
            cursor = resume;
            continue;
        }

        cursor += wanted - (longest_pattern - 1);
    }

    return matched;
}

EXPORT_SYMBOL_GPL(tk_scan_ranges);

unsigned int tk_scan_ranges(struct task_struct* task, const struct tk_address_range* ranges, unsigned int range_count,
                            const struct tk_pattern* patterns, unsigned int pattern_count,
                            struct tk_scan_result* results, void* buffer, size_t buffer_size)
{
    size_t longest_pattern = 0;
    unsigned int matched = 0;
    unsigned int i;

    memset(results, 0, pattern_count * sizeof(results[0]));

    for (i = 0; i < pattern_count; i++)
    {
        longest_pattern = max(longest_pattern, patterns[i].length);
    }
    if (!longest_pattern || longest_pattern > buffer_size)
    {
        return 0;
    }

    for (i = 0; i < range_count && matched < pattern_count; i++)
    {
        matched += scan_one_range(task, &ranges[i], patterns, pattern_count, results, buffer, buffer_size,
                                  longest_pattern, pattern_count - matched);
    }

    return matched;
}
