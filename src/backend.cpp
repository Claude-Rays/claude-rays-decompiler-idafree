// Claude-Rays Decompiler - query backend: the Claude Code CLI
#include "backend.hpp"

#include <algorithm>

namespace clauderays
{

//------------------------------------------------------------------------------
// Claude Code CLI: role prompt and the structured output schema
//------------------------------------------------------------------------------
static const char SYSTEM_PROMPT[] =
  "You are a decompiler inside IDA. The user message describes ONE function "
  "of a binary, extracted from the IDA database by a plugin, and you turn its "
  "disassembly into readable, faithful C.\n"
  "\n"
  "The input has labelled sections:\n"
  "- Function: name, address range, architecture, prototype and calling "
  "convention when IDA knows them, whether it returns.\n"
  "- Stack frame: arguments and local variables with their frame offset, "
  "size, type and name, as the listing refers to them.\n"
  "- Listing: the disassembly, split in basic blocks. Each block header says "
  "its number, successors, kind (return, noreturn, indirect jump) and loop "
  "structure (loop header with its back edges, loop membership). Each line "
  "is '<address> <instruction>' and may end with '; ' facts computed by the "
  "plugin from the instruction semantics: the signedness of conditional "
  "jumps ('signed <', 'unsigned >=', '==', 'float <' after a float compare, "
  "with the instruction that set the flags), the size of memory accesses "
  "('load u8', 'store u32', 'load i16 sign-extend', 'zero-extend'), calls "
  "('noreturn', 'indirect', 'result used' / 'result ignored') and constants "
  "(ASCII characters, names). These facts are exact: use them as they are, "
  "never re-derive signedness, sizes or loops yourself.\n"
  "- Switch: the jump tables with the case values of each target.\n"
  "- Called functions: prototype and comment of each callee; the complete "
  "listing of small unnamed callees.\n"
  "- Call sites: how some callers prepare the arguments of this function.\n"
  "- Data: strings, globals and their values referenced by the function.\n"
  "- Types: definitions of the structures and enums used.\n"
  "- Requested context: extra context you asked for in an earlier round.\n"
  "Some sections may be missing or cut for size.\n"
  "\n"
  "Rules:\n"
  "- Faithfulness before beauty. Do not invent calls, conditions, constants "
  "or side effects. Every call of the listing appears in the code, with the "
  "callee name as written in the listing (or the name of the import). "
  "When something is unclear, write it literally (e.g. a memory access "
  "through a cast pointer: *(uint32_t *)(p + 0x10)) and add it to "
  "'uncertain'.\n"
  "- Reconstruct the intent: structured loops and ifs instead of gotos when "
  "the CFG allows it, switch statements, compiler idioms (division by "
  "multiplication, inlined memset/strlen, stack cookies, SEH), API calls "
  "with their symbolic constants. Propose descriptive names for variables "
  "(snake_case) and keep the names that the database already has.\n"
  "- Use standard C with <stdint.h> types, Windows types when the binary is "
  "a Windows program, and the structure types given in the input.\n"
  "- Write every call to a C++ method the same way, with the qualified name "
  "and the object as first argument: Cls::Method(this, a, b). Never drop "
  "the object or the qualification, even for methods of the same class.\n"
  "- Keep the constants of the listing exactly: the size of a local array "
  "comes from the stack frame offsets, an index or length from the "
  "immediates of the instructions. Do not round them or replace them with "
  "the values a known source would use; when you recognize the original "
  "source (a library, a known algorithm), say it in the summary but "
  "translate what the binary does.\n"
  "- Explain the code like an analyst reading it for the first time: add "
  "short analysis comments ('// ...' at the end of a statement line or on "
  "their own line) where the meaning is not obvious: what a field, flag or "
  "constant is, why a branch exists, what a loop computes, which compiler "
  "idiom was undone. Not on every line, and never restating the code. "
  "Comment lines do not need an address annotation.\n"
  "\n"
  "Answer fields:\n"
  "- summary: the header comment of the function, plain text without "
  "comment markers, lines of at most 100 characters: first what the "
  "function does in one or two sentences; then its parameters and return "
  "value; then side effects, the algorithm or notable details, and the "
  "original source when recognized.\n"
  "- prototype: the C declaration of the function, with calling convention, "
  "e.g. \"int __fastcall parse_header(const uint8_t *buf, size_t len)\". "
  "Keep the existing function name unless it is a default name (sub_...).\n"
  "- code: the complete C definition of the function (prototype line and "
  "body). EVERY statement, and every if/while/for/switch/case line, is "
  "preceded by an address comment with the address of its first "
  "instruction, written exactly as /*0x401020*/ (lowercase hex, 0x prefix), "
  "e.g. '/*0x401020*/ if ( len < 4 )'. Declarations without an initializer "
  "have no address comment. Every basic block of the listing must be "
  "covered by at least one address comment that points inside it.\n"
  "- uncertain: the places where you are not sure of the translation, each "
  "with the instruction address and the reason. An empty array if none.\n"
  "- need_more: context that is missing to decompile the function well and "
  "that the plugin can extract: 'function' (the listing of a function, e.g. "
  "a callee whose behaviour matters or a pointer called indirectly), "
  "'data' (value, type and uses of a global) or 'struct' (definition of a "
  "type). target is an address (0x...) or a name from the input. At most 5 "
  "entries; an empty array when the context is enough. Even when you ask "
  "for more, give your best complete answer in the other fields.\n"
  "Answer only with the structured output.";

static const char SCHEMA[] =
  "{\"type\":\"object\","
  "\"properties\":{"
    "\"summary\":{\"type\":\"string\"},"
    "\"prototype\":{\"type\":\"string\"},"
    "\"code\":{\"type\":\"string\"},"
    "\"uncertain\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
      "\"properties\":{\"address\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"}},"
      "\"required\":[\"address\",\"reason\"],\"additionalProperties\":false}},"
    "\"need_more\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
      "\"properties\":{\"what\":{\"type\":\"string\",\"enum\":[\"function\",\"data\",\"struct\"]},"
        "\"target\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"}},"
      "\"required\":[\"what\",\"target\",\"reason\"],\"additionalProperties\":false}}},"
  "\"required\":[\"summary\",\"prototype\",\"code\",\"uncertain\",\"need_more\"],"
  "\"additionalProperties\":false}";

//------------------------------------------------------------------------------
// Decompile and analyze: appended to SYSTEM_PROMPT, and 'findings' added to SCHEMA
//------------------------------------------------------------------------------
static const char ANALYZE_PROMPT[] =
  "\n"
  "\n"
  "Security analysis: besides the decompilation, review the function as a "
  "vulnerability researcher and report what you find in 'findings'. You "
  "see this function alone: its callers, the origin of its arguments and "
  "the invariants kept elsewhere are unknown, so say what you assume.\n"
  "\n"
  "- findings: at most 8 entries, the most important first; an empty array "
  "when nothing stands out (a correct answer, not a failure: do not pad it "
  "with generic advice). Each entry has:\n"
  "  - level: how sure the bug is, judged from this function alone:\n"
  "    'confirmed': the bug is in the code whatever the callers do, e.g. a "
  "copy into a fixed-size local buffer with a length that is not checked "
  "against it, an off-by-one with constant sizes, a use after free or a "
  "double free within the function, a non-literal format string, the "
  "result of an allocation used without a check.\n"
  "    'possible': the bug exists only if a precondition the function does "
  "not check holds, e.g. the caller controls a length, an index or a "
  "pointer that reaches a copy, an allocation size or an array access.\n"
  "    'theoretical': a risky pattern or API without evidence of a bug, "
  "e.g. strcpy of a source that looks bounded, an arithmetic that could "
  "overflow only with unrealistic values.\n"
  "  - class: the kind of bug (stack buffer overflow, heap buffer overflow, "
  "out-of-bounds read, integer overflow, integer truncation, signedness "
  "error, use after free, double free, null dereference, uninitialized "
  "memory, format string, race condition, type confusion, information "
  "leak, command injection, path traversal, missing check...).\n"
  "  - addresses: the instruction addresses of the listing where the bug "
  "happens (the faulty copy, access, call or arithmetic), every one an "
  "instruction address of this function, written as 0x401020. At least "
  "one. These addresses are highlighted in the code: point at the "
  "instructions of the bug, not at the whole function.\n"
  "  - description: what goes wrong and how, in terms of the code (names "
  "of the variables as in your C).\n"
  "  - precondition: what must hold outside this function for the bug to "
  "be reachable (who controls which value), or 'none' for confirmed bugs.\n"
  "Base every finding on the code: no CVE numbers, no guesses about other "
  "functions presented as facts.\n"
  "Answer only with the structured output.";

static const char FINDINGS_SCHEMA[] =
  ",\"findings\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
    "\"properties\":{"
      "\"level\":{\"type\":\"string\",\"enum\":[\"confirmed\",\"possible\",\"theoretical\"]},"
      "\"class\":{\"type\":\"string\"},"
      "\"addresses\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
      "\"description\":{\"type\":\"string\"},"
      "\"precondition\":{\"type\":\"string\"}},"
    "\"required\":[\"level\",\"class\",\"addresses\",\"description\",\"precondition\"],"
    "\"additionalProperties\":false}}},"
  "\"required\":[\"summary\",\"prototype\",\"code\",\"uncertain\",\"need_more\",\"findings\"],"
  "\"additionalProperties\":false}";

const std::string &analyze_system_prompt()
{
  static const std::string s = std::string(SYSTEM_PROMPT) + ANALYZE_PROMPT;
  return s;
}

const std::string &analyze_schema()
{
  // SCHEMA up to the end of its properties, then the findings and the new required list
  static const std::string s = [] ()
  {
    std::string base = SCHEMA;
    return base.substr(0, base.rfind("},\"required\":")) + FINDINGS_SCHEMA;
  }();
  return s;
}

//------------------------------------------------------------------------------
static void run_claude_cli(job_t *job)
{
  std::string exe = find_executable(job->claude_path);
  if ( exe.empty() )
  {
    job->error = "the Claude Code CLI ('" + job->claude_path + "') was not found. Install it "
                 "(irm https://claude.ai/install.ps1 | iex), log in once with 'claude' + /login, "
                 "or set its full path in Claude-Rays Decompiler/Settings";
    return;
  }
  std::vector<std::string> args =
  {
    "-p",
    "--output-format", "json",
    "--model", job->model,
    "--system-prompt", job->system_prompt.empty() ? SYSTEM_PROMPT : job->system_prompt,
    "--json-schema", job->schema.empty() ? SCHEMA : job->schema,
    "--tools", "",                // no tools: it only answers
    "--strict-mcp-config",        // none of the user's MCP servers
    "--setting-sources", "",      // none of the user's settings / CLAUDE.md
    "--no-session-persistence",
  };
  if ( !job->effort.empty() )
  {
    args.push_back("--effort");
    args.push_back(job->effort);
  }
  // a neutral directory, so no project CLAUDE.md is picked up
  std::string cwd = neutral_work_dir();
  // the prompt goes through stdin: no command line length limit, no quoting
  job->ok = job->proc.run(exe, args, cwd, job->prompt, job->timeout,
                          &job->response, &job->errout, &job->exit_code, &job->error);
  if ( !job->ok )
    job->error = "running " + exe + ": " + job->error;
}

//------------------------------------------------------------------------------
void run_job(job_t *job)
{
  run_claude_cli(job);
  job->done = true;
}

void cancel_job(job_t *job)
{
  job->proc.cancel();
}

//------------------------------------------------------------------------------
// the answer as text may come wrapped in a ```json fence
static std::string strip_fence(const std::string &text)
{
  std::string t = trim(text);
  if ( t.compare(0, 3, "```") != 0 )
    return t;
  size_t nl = t.find('\n');
  size_t end = t.rfind("```");
  if ( nl == std::string::npos || end == std::string::npos || end <= nl )
    return t;
  return trim(t.substr(nl + 1, end - nl - 1));
}

static std::string error_hint(const std::string &text)
{
  std::string low = text;
  for ( auto &c : low )
    c = char(tolower((unsigned char)c));
  if ( low.find("login") != std::string::npos
    || low.find("log in") != std::string::npos
    || low.find("authenticat") != std::string::npos
    || low.find("api key") != std::string::npos )
  {
    return "\nRun 'claude' in a terminal and log in with /login (Claude Pro/Max account).";
  }
  if ( low.find("usage limit") != std::string::npos
    || low.find("rate limit") != std::string::npos
    || low.find("limit reached") != std::string::npos )
  {
    return "\nThe usage limit of your plan was reached: wait for it to reset.";
  }
  return std::string();
}

// the numeric value of a member, 0 if missing
static double num_of(const json_t *j, const char *key)
{
  const json_t *v = j != nullptr ? j->get(key) : nullptr;
  return v != nullptr && v->type == json_t::JNUM ? v->num : 0;
}

// cost, tokens and the model that answered; modelUsage is keyed by the full
// model id (the one that cost the most if the CLI used several)
void usage_t::add(const usage_t &u)
{
  if ( !u.model_id.empty() )
    model_id = u.model_id;
  cost_usd += u.cost_usd;
  input_tokens += u.input_tokens;
  output_tokens += u.output_tokens;
  safety_stops += u.safety_stops;
  for ( const auto &m : u.models )
    if ( std::find(models.begin(), models.end(), m) == models.end() )
      models.push_back(m);
}

std::string safety_note(int stops, const std::vector<std::string> &models)
{
  if ( stops <= 0 )
    return std::string();
  std::string who;
  for ( const auto &m : models )
    who += (who.empty() ? "" : " + ") + m;
  return strfmt("Claude's safety checks stopped this answer %d time(s); it was completed by %s. A "
                "fallback model may be less precise.", stops, who.empty() ? "the CLI" : who.c_str());
}

std::string safety_error(const usage_t &u, const json_t *result, const std::string &err)
{
  if ( u.safety_stops <= 0 )
    return err;
  std::string why = result != nullptr ? one_line(result->str("summary"), 400) : std::string();
  return strfmt("Claude's safety checks stopped this answer (%d safety stop(s)) and it came back "
                "without its content%s. This can happen with the security review of code that looks like an "
                "exploit target. It is not retried automatically; Regenerate asks again in a new query.",
                u.safety_stops, why.empty() ? "" : (": \"" + why + "\"").c_str());
}

static void read_usage(const json_t &outer, usage_t *u)
{
  u->cost_usd = num_of(&outer, "total_cost_usd");
  const json_t *usage = outer.get("usage");
  u->input_tokens = int64(num_of(usage, "input_tokens") + num_of(usage, "cache_read_input_tokens")
                        + num_of(usage, "cache_creation_input_tokens"));
  u->output_tokens = int64(num_of(usage, "output_tokens"));
  u->safety_stops = int(num_of(&outer, "safety_stops"));
  const json_t *mu = outer.get("modelUsage");
  double best = -1;
  if ( mu != nullptr && mu->is_obj() )
  {
    for ( const auto &kv : mu->obj )
    {
      u->models.push_back(kv.first);
      double c = num_of(&kv.second, "costUSD");
      if ( c > best )
      {
        best = c;
        u->model_id = kv.first;
      }
    }
  }
}

bool extract_result(const job_t &job, json_t *out, std::string *err, usage_t *usage)
{
  std::string stdout_text = trim(job.response);
  std::string stderr_text = trim(job.errout);
  json_t outer;
  std::string e;
  if ( stdout_text.empty() || !json_parse(stdout_text, &outer, &e) || !outer.is_obj() )
  {
    std::string details = !stderr_text.empty() ? stderr_text : stdout_text;
    if ( details.empty() )
      details = "(no output)";
    *err = strfmt("the Claude Code CLI exited with code %d without a valid answer:\n%s%s",
                  job.exit_code, details.substr(0, 2000).c_str(), error_hint(details).c_str());
    return false;
  }

  if ( usage != nullptr )
    read_usage(outer, usage);

  if ( settings().verbose )
  {
    const json_t *tok = outer.get("usage");
    log_debug("claude-cli: %s, %s turn(s), %s ms, cost %s USD (plan usage), "
              "tokens in %s (cache read %s, cache write %s) / out %s",
              outer.str("subtype").c_str(), outer.str("num_turns").c_str(),
              outer.str("duration_ms").c_str(), outer.str("total_cost_usd").c_str(),
              tok != nullptr ? tok->str("input_tokens").c_str() : "?",
              tok != nullptr ? tok->str("cache_read_input_tokens").c_str() : "?",
              tok != nullptr ? tok->str("cache_creation_input_tokens").c_str() : "?",
              tok != nullptr ? tok->str("output_tokens").c_str() : "?");
    const json_t *mu = outer.get("modelUsage");
    if ( mu != nullptr && mu->is_obj() )
      for ( const auto &kv : mu->obj )
        log_debug("claude-cli: model used: %s", kv.first.c_str());
    if ( num_of(&outer, "safety_stops") > 0 )
      log_debug("claude-cli: %s safety stop(s)", outer.str("safety_stops").c_str());
    if ( !stderr_text.empty() )
      log_debug_text("claude-cli stderr:", stderr_text);
    log_debug_text("claude-cli output:", stdout_text);
  }

  const json_t *is_error = outer.get("is_error");
  if ( (is_error != nullptr && is_error->type == json_t::JBOOL && is_error->b)
    || job.exit_code != 0 )
  {
    std::string msg = outer.str("result");
    if ( msg.empty() )
      msg = !stderr_text.empty() ? stderr_text : outer.str("subtype");
    std::string api = outer.str("api_error_status");
    *err = strfmt("the Claude Code CLI reported an error (exit code %d%s%s): %s%s",
                  job.exit_code,
                  api.empty() || api == "null" ? "" : ", API status ",
                  api.empty() || api == "null" ? "" : api.c_str(),
                  msg.substr(0, 2000).c_str(), error_hint(msg).c_str());
    return false;
  }

  // with --json-schema the validated object comes in structured_output
  const json_t *so = outer.get("structured_output");
  if ( so != nullptr && so->is_obj() )
  {
    *out = *so;
    log_debug_text("model answer:", out->dump());
    return true;
  }
  // fall back to the text answer
  std::string t = strip_fence(outer.str("result"));
  log_debug_text("model answer:", t);
  if ( !json_parse(t, out, &e) )
  {
    *err = "error unpacking response (" + e + ")\n" + t.substr(0, 2000);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool decode_result(const json_t &j, decomp_result_t *out, std::string *err)
{
  if ( !j.is_obj() )
  {
    *err = "the answer is not an object";
    return false;
  }
  out->summary = trim(j.str("summary"));
  out->prototype = trim(j.str("prototype"));
  out->code = j.str("code");
  // normalize the line ends
  std::string code;
  for ( char c : out->code )
    if ( c != '\r' )
      code += c;
  out->code = code;
  if ( trim(out->code).empty() )
  {
    *err = "the answer has no code";
    return false;
  }
  out->uncertain.clear();
  const json_t *u = j.get("uncertain");
  if ( u != nullptr && u->is_arr() )
    for ( const auto &x : u->arr )
      if ( x.is_obj() )
        out->uncertain.push_back({ trim(x.str("address")), trim(x.str("reason")) });
  out->need_more.clear();
  const json_t *n = j.get("need_more");
  if ( n != nullptr && n->is_arr() )
    for ( const auto &x : n->arr )
      if ( x.is_obj() && !trim(x.str("target")).empty() )
        out->need_more.push_back({ trim(x.str("what")), trim(x.str("target")), trim(x.str("reason")) });
  out->findings = decode_findings(j.get("findings"));
  return true;
}

//------------------------------------------------------------------------------
std::vector<finding_t> decode_findings(const json_t *a)
{
  std::vector<finding_t> out;
  if ( a == nullptr || !a->is_arr() )
    return out;
  for ( const auto &x : a->arr )
  {
    if ( !x.is_obj() )
      continue;
    finding_t f;
    // a known level, theoretical otherwise
    f.level = trim(x.str("level"));
    for ( auto &c : f.level )
      c = char(tolower((unsigned char)c));
    if ( f.level != "confirmed" && f.level != "possible" )
      f.level = "theoretical";
    f.cls = trim(x.str("class"));
    const json_t *addrs = x.get("addresses");
    if ( addrs != nullptr && addrs->is_arr() )
      for ( const auto &ad : addrs->arr )
        if ( !trim(ad.as_text()).empty() )
          f.addresses.push_back(trim(ad.as_text()));
    f.description = trim(x.str("description"));
    f.precondition = trim(x.str("precondition"));
    out.push_back(f);
  }
  std::stable_sort(out.begin(), out.end(),
                   [] (const finding_t &l, const finding_t &r) { return l.rank() < r.rank(); });
  return out;
}

json_t encode_findings(const std::vector<finding_t> &findings)
{
  auto jstr = [] (const std::string &s)
  {
    json_t j;
    j.type = json_t::JSTR;
    j.s = s;
    return j;
  };
  json_t a;
  a.type = json_t::JARRAY;
  for ( const auto &f : findings )
  {
    json_t o;
    o.type = json_t::JOBJECT;
    o.obj.push_back({ "level", jstr(f.level) });
    o.obj.push_back({ "class", jstr(f.cls) });
    json_t addrs;
    addrs.type = json_t::JARRAY;
    for ( const auto &s : f.addresses )
      addrs.arr.push_back(jstr(s));
    o.obj.push_back({ "addresses", addrs });
    o.obj.push_back({ "description", jstr(f.description) });
    o.obj.push_back({ "precondition", jstr(f.precondition) });
    a.arr.push_back(o);
  }
  return a;
}

} // namespace clauderays
