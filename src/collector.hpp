// Claude-Rays Decompiler - context collector
// The deterministic equivalent of what Claude would look up with tools: each
// step of that analysis becomes a section extracted with the SDK. Runs in the
// main thread, before the job is started.
#pragma once

#include "common.hpp"
#include "backend.hpp"

#include <set>

namespace clauderays
{

struct collected_t
{
  std::string text;                 // the user message
  std::string body;                 // the sections alone, without the task line
  std::string error;               // not empty: nothing to send (too large...)
  size_t ninsns = 0;
  // size of each section, for the verbose log
  std::vector<std::pair<std::string, size_t>> sizes;
};

// the context of the function containing 'func_ea'; 'budget' 0 uses the
// one of the settings
bool collect_function_context(ea_t func_ea, collected_t *out, size_t budget = 0);

// one need_more round: the context for the valid requests, "" if none.
// 'seen' keeps the requests already served (across rounds); the requests
// that cannot be served are described in *ignored
std::string collect_requested(
        const std::vector<need_more_t> &reqs,
        std::set<std::string> *seen,
        size_t budget,
        std::vector<std::string> *ignored);

// the functions called by 'pfn' (directly, through an import pointer or by a
// tail jump), in order of appearance
std::vector<ea_t> function_callees(func_t *pfn);

// number of instructions of the function (all chunks)
size_t count_insns(func_t *pfn);

} // namespace clauderays
