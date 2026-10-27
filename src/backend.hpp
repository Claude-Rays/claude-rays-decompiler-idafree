// Claude-Rays Decompiler - query backend
// Runs the Claude Code CLI ("claude -p") as a child process with the
// decompiler system prompt and schema, and extracts the validated answer.
#pragma once

#include "common.hpp"
#include "json.hpp"
#include "process.hpp"

#include <atomic>
#include <thread>

namespace clauderays
{

//------------------------------------------------------------------------------
// one query to the model running in a background thread
//------------------------------------------------------------------------------
struct job_t
{
  // input
  std::string model;
  std::string effort;         // "" = not passed (the CLI default)
  std::string claude_path;
  int timeout = 0;
  std::string prompt;
  // "" = the decompiler ones; the diff of two versions has its own (pair.cpp)
  std::string system_prompt;
  std::string schema;

  // output, written by the worker thread before 'done' is set
  bool ok = false;            // the process ran
  int exit_code = 0;
  std::string response;       // stdout
  std::string errout;         // stderr
  std::string error;
  std::atomic<bool> done{ false };

  process_run_t proc;
  std::thread thread;
};

// worker thread body: run the query, then set 'done'
void run_job(job_t *job);

// thread-safe: abort the query in flight
void cancel_job(job_t *job);

// what one query used, as reported by the CLI
struct usage_t
{
  std::string model_id;       // the model that answered ("" if not reported)
  double cost_usd = 0;        // at API prices
  int64 input_tokens = 0;     // including the cache reads and writes
  int64 output_tokens = 0;
  // how many times Claude's safety checks stopped the answer (the CLI's
  // safety_stops); after a stop the CLI may finish it with another model
  int safety_stops = 0;
  std::vector<std::string> models;    // every model that took part in the answer

  void add(const usage_t &u);
};

// The note of an answer completed after a safety stop ("" if none): the
// analysis of a function that looks like an exploit target can trip Claude's
// safety checks, and the CLI then finishes with another model.
std::string safety_note(int stops, const std::vector<std::string> &models);

// The error of an answer that a safety stop left without its content, with
// the explanation the model gave (the 'summary' of 'result'), or 'err'
// unchanged when there was no stop. It is not retried: Regenerate asks again.
std::string safety_error(const usage_t &u, const json_t *result, const std::string &err);

// Main thread, once 'done' is set and job.ok is true: the model's answer as a
// JSON object. On failure fills *err with a readable message. *usage, if
// given, is filled whenever the CLI output could be parsed.
bool extract_result(const job_t &job, json_t *out, std::string *err, usage_t *usage = nullptr);

//------------------------------------------------------------------------------
// the decoded answer
//------------------------------------------------------------------------------
struct uncertain_t
{
  std::string address;
  std::string reason;
};

struct need_more_t
{
  std::string what;           // function, data or struct
  std::string target;         // an address or a name
  std::string reason;
};

// one finding of the security analysis (Decompile and analyze)
struct finding_t
{
  std::string level;                    // confirmed, possible or theoretical
  std::string cls;                      // the kind of bug
  std::vector<std::string> addresses;   // instructions of the bug
  std::string description;
  std::string precondition;             // what must hold outside the function

  // 0 confirmed, 1 possible, 2 theoretical: the lower, the more severe
  int rank() const { return level == "confirmed" ? 0 : level == "possible" ? 1 : 2; }
};

struct decomp_result_t
{
  std::string summary;          // header comment, plain text
  std::string prototype;
  std::string code;
  std::vector<uncertain_t> uncertain;
  std::vector<need_more_t> need_more;
  std::vector<finding_t> findings;      // the security analysis, when it was asked for
};

bool decode_result(const json_t &j, decomp_result_t *out, std::string *err);

//------------------------------------------------------------------------------
// Decompile and analyze: the decompiler prompt and schema plus the security
// review of the function
//------------------------------------------------------------------------------
const std::string &analyze_system_prompt();
const std::string &analyze_schema();

// the findings of an answer (or of a cached entry), the most severe first
std::vector<finding_t> decode_findings(const json_t *a);
json_t encode_findings(const std::vector<finding_t> &findings);

} // namespace clauderays
