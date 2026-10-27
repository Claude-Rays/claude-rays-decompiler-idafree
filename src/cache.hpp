// Claude-Rays Decompiler - results cached in the database
// A netnode ("$ clauderays") with one blob per function and command, keyed by
// the start address of the function, holding a JSON object: the result of a
// command never hides or replaces the result of another. The hash of the
// function bytes decides if a result is still valid; the hash of the callee
// names only marks it stale.
#pragma once

#include "common.hpp"
#include "backend.hpp"
#include "fixes.hpp"

namespace clauderays
{

struct cache_entry_t
{
  std::string bytes_hash;
  std::string names_hash;
  std::string model;                    // as asked: an alias or an id
  std::string model_id;                 // the model that answered ("" if unknown)
  std::string effort;                   // "" = the CLI default
  std::string date;
  double cost_usd = 0;                  // all rounds, at API prices
  int64 input_tokens = 0;               // all rounds
  int64 output_tokens = 0;
  std::string summary;
  std::string prototype;
  std::string code;
  std::vector<uncertain_t> uncertain;
  std::vector<std::string> warnings;    // validation
  std::vector<std::string> missing;     // need_more left unanswered
  int rounds = 0;                       // need_more rounds served
  bool analyzed = false;                // made by Decompile and analyze
  std::vector<finding_t> findings;      // anchored to instructions of the function
  int safety_stops = 0;                 // of all rounds (usage_t)
  std::vector<std::string> models;      // every model that answered
  // Decompile, analyze and patch: the fixes of the findings (has_fix false: never asked for)
  bool has_fix = false;
  fix_result_t fix;
  // the command (cache_mode_t) whose cached result this one was taken from;
  // -1: its own (not saved)
  int derived_from = -1;
};

// the command a result comes from: each has its cached result and its view
enum cache_mode_t
{
  CM_DECOMPILE,     // Decompile
  CM_ANALYZE,       // Decompile and analyze
  CM_PATCH,         // Decompile, analyze and patch
};
static const cache_mode_t CACHE_MODES[] = { CM_DECOMPILE, CM_ANALYZE, CM_PATCH };

inline cache_mode_t cache_mode_of(bool analyze, bool patch)
{
  return patch ? CM_PATCH : analyze ? CM_ANALYZE : CM_DECOMPILE;
}

// "decompile", "analyze", "patch" (as saved with the desktop)
const char *cache_mode_key(cache_mode_t m);
// the name of the command: "Decompile and analyze"
const char *cache_mode_label(cache_mode_t m);

enum cache_state_t
{
  CS_NONE,          // nothing cached (or the bytes changed: dropped)
  CS_VALID,
  CS_STALE,         // the callee names changed
};

// "sonnet -> claude-sonnet-5-5", or just the model when both match or the
// answering model is unknown (results cached by older versions)
std::string model_used_str(const cache_entry_t &e);

// the cached result of the function starting at 'func_ea' made by 'mode'
cache_state_t cache_load(ea_t func_ea, cache_mode_t mode, cache_entry_t *out);
void cache_save(ea_t func_ea, cache_mode_t mode, const cache_entry_t &e);

// The cached result made by 'mode' or, without one, the one taken from the
// cached result of a more complete command, with nothing queried: Decompile
// and analyze is Decompile, analyze and patch without the fixes, and
// Decompile is either of them without the analysis (the code is the same).
// The result taken is not saved: Regenerate makes one of its own.
cache_state_t cache_load_or_derive(ea_t func_ea, cache_mode_t mode, cache_entry_t *out);
void cache_delete(ea_t func_ea, cache_mode_t mode);

// hashes of the current state of the function
std::string func_bytes_hash(ea_t func_ea);
std::string func_names_hash(ea_t func_ea);

} // namespace clauderays
