// Claude-Rays Decompiler - diff of two versions of a function in one query
#include "pair.hpp"
#include "backend.hpp"
#include "cache.hpp"
#include "collector.hpp"
#include "json.hpp"
#include "models.hpp"
#include "validate.hpp"
#include "view.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <netnode.hpp>

#include <algorithm>
#include <map>
#include <memory>
#include <set>

namespace clauderays
{

static const int WAIT_MS = 50;              // wait box loop step
static const size_t MAX_ASM_DIFF_LINES = 400;
static const int FACTS_COLUMN = 48;

//------------------------------------------------------------------------------
// prompt and schema of the pair: the decompiler rules plus alignment, the
// list of changes and their assessment
//------------------------------------------------------------------------------
static const char PAIR_SYSTEM_PROMPT[] =
  "You are a decompiler and a patch analyst inside IDA. The user message "
  "describes TWO versions of the same function of a binary, OLD (before a "
  "patch) and NEW (after it), extracted by a plugin. You decompile both into "
  "readable, faithful C, aligned so that a line diff of the two shows only "
  "the real changes, list the changes and assess whether they fix a "
  "security problem.\n"
  "\n"
  "The input has:\n"
  "- Assembly diff: a unified diff of the two listings without addresses "
  "(OLD -> NEW). It is the ground truth of what changed in the binary: use "
  "it to find every difference and do not report differences it does not "
  "show.\n"
  "- One part per version, OLD first, each with labelled sections: Function "
  "(name, address range, prototype, comment), Listing (the disassembly split "
  "in basic blocks, each line '<address> <instruction>', possibly followed "
  "by '; ' facts or comments), Called functions, and, for the version of the "
  "open database, also Stack frame, Switch, Call sites, Data and Types. The "
  "other version comes from an exported database and has less context: no "
  "frame, no types, and the instruction facts are missing. Its addresses are "
  "its own, not those of the open database. Facts given for one version "
  "(signedness of jumps, access sizes, types, names) also hold for the same "
  "code in the other version.\n"
  "\n"
  "Rules for the code (both versions):\n"
  "- Faithfulness before beauty. Do not invent calls, conditions, constants "
  "or side effects. Every call of a listing appears in the code of that "
  "version, with the callee name as written in the listing. When something "
  "is unclear, write it literally (e.g. *(uint32_t *)(p + 0x10)) and add it "
  "to 'uncertain' of that version.\n"
  "- Reconstruct the intent: structured loops and ifs instead of gotos, "
  "switch statements, compiler idioms undone, API calls with their symbolic "
  "constants. Use standard C with <stdint.h> types, Windows types when the "
  "binary is a Windows program, and the structure types given in the input.\n"
  "- Write every call to a C++ method with the qualified name and the object "
  "as first argument: Cls::Method(this, a, b).\n"
  "- Keep the constants of each listing exactly.\n"
  "- EVERY statement, and every if/while/for/switch/case line, is preceded "
  "by an address comment with the address of its first instruction IN THAT "
  "VERSION, written exactly as /*0x401020*/ (lowercase hex, 0x prefix). "
  "Declarations without an initializer have none. Every basic block must be "
  "covered by at least one address comment that points inside it. The "
  "plugin removes the address comments before showing the diff.\n"
  "- Add short analysis comments ('// ...') where the meaning is not "
  "obvious, never restating the code. Comments are about behaviour: never "
  "comment on code generation (registers, stack slots, reloads, spills, "
  "hoisted invariants, block order, inlining), since it differs between "
  "versions without changing the C and only adds noise to the diff.\n"
  "\n"
  "Alignment (the most important rule):\n"
  "- Where the behaviour is the same, the two versions must be IDENTICAL "
  "line by line: the same variable names, types, statement order, "
  "structure, line breaks and comments. Differences may appear only where "
  "the binary changed. Register allocation, block order, stack offsets or "
  "instruction scheduling that differ without changing the behaviour do not "
  "change the C.\n"
  "- Decompile NEW first in your mind, then write OLD reusing its text for "
  "the unchanged parts (or the other way round): never rename or reword an "
  "unchanged part in one version only.\n"
  "- When a structure grew and its field offsets moved, use the same field "
  "names in both versions.\n"
  "- Comments follow the same rule: in the unchanged parts both versions "
  "have the same comments, word for word, on the same lines; never a "
  "comment on one side only. A comment that explains a change goes only on "
  "the changed lines. The explanation of the changes belongs in 'changes' "
  "and 'assessment', not in comments of the unchanged code.\n"
  "- Write the WIL diagnostics (Return_Hr, Return_Win32, Log_Hr...) with "
  "the line number and file of each listing as they are: the plugin "
  "ignores those line numbers in the diff.\n"
  "\n"
  "Answer fields:\n"
  "- old, new: the decompilation of each version. summary: what the function "
  "does, plain text, lines of at most 100 characters; for NEW also what "
  "changed. prototype: the C declaration. code: the complete C definition "
  "(prototype line and body), annotated as said. uncertain: the doubtful "
  "places with the instruction address of that version and the reason.\n"
  "- changes: one entry per behavioural change: kind 'added', 'removed' or "
  "'modified'; old_addresses and new_addresses: the instruction addresses "
  "of the change in each listing (empty only for the side where the code "
  "does not exist), every one an address of that listing; description: what "
  "changed, in terms of the code. Group all compiler-only differences "
  "(registers, block order, inlining, moved structure offsets) in a single "
  "entry of kind 'compiler', never as behavioural changes. Every hunk of the "
  "assembly diff is explained by some entry. An empty array if nothing "
  "changed.\n"
  "- assessment: security_relevant 'likely', 'possible' or 'unlikely'; "
  "class: the kind of fix (race condition, buffer overflow, integer "
  "overflow, use after free, double free, bounds check, null check, "
  "uninitialized memory, type confusion, information leak, hardening, "
  "functional change, refactoring...); reasoning: what the change prevents "
  "and why, based only on the code; confidence 'high', 'medium' or 'low'; "
  "follow_up: what to check next to confirm it, e.g. other functions to "
  "compare ('do SetValue and RemoveValue take the same lock?').\n"
  "  Recognize the usual fix patterns of Microsoft binaries: WIL feature "
  "flags (wil::details::FeatureImpl<...>::__private_IsEnabled, "
  "Feature_..._IsEnabled) guarding the new code with the old branch kept as "
  "the kill switch, added length or overflow checks, locks, reference "
  "counts, initializations, memcpy replaced by a safe variant. Never invent "
  "CVE numbers. It is a hypothesis: say what is uncertain.\n"
  "Answer only with the structured output.";

#define PAIR_SIDE_SCHEMA \
  "{\"type\":\"object\"," \
  "\"properties\":{" \
    "\"summary\":{\"type\":\"string\"}," \
    "\"prototype\":{\"type\":\"string\"}," \
    "\"code\":{\"type\":\"string\"}," \
    "\"uncertain\":{\"type\":\"array\",\"items\":{\"type\":\"object\"," \
      "\"properties\":{\"address\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"}}," \
      "\"required\":[\"address\",\"reason\"],\"additionalProperties\":false}}}," \
  "\"required\":[\"summary\",\"prototype\",\"code\",\"uncertain\"]," \
  "\"additionalProperties\":false}"

static const char PAIR_SCHEMA[] =
  "{\"type\":\"object\","
  "\"properties\":{"
    "\"old\":" PAIR_SIDE_SCHEMA ","
    "\"new\":" PAIR_SIDE_SCHEMA ","
    "\"changes\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
      "\"properties\":{"
        "\"kind\":{\"type\":\"string\",\"enum\":[\"added\",\"removed\",\"modified\",\"compiler\"]},"
        "\"old_addresses\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
        "\"new_addresses\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
        "\"description\":{\"type\":\"string\"}},"
      "\"required\":[\"kind\",\"old_addresses\",\"new_addresses\",\"description\"],"
      "\"additionalProperties\":false}},"
    "\"assessment\":{\"type\":\"object\","
      "\"properties\":{"
        "\"security_relevant\":{\"type\":\"string\",\"enum\":[\"likely\",\"possible\",\"unlikely\"]},"
        "\"class\":{\"type\":\"string\"},"
        "\"reasoning\":{\"type\":\"string\"},"
        "\"confidence\":{\"type\":\"string\",\"enum\":[\"high\",\"medium\",\"low\"]},"
        "\"follow_up\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},"
      "\"required\":[\"security_relevant\",\"class\",\"reasoning\",\"confidence\",\"follow_up\"],"
      "\"additionalProperties\":false}},"
  "\"required\":[\"old\",\"new\",\"changes\",\"assessment\"],"
  "\"additionalProperties\":false}";

//------------------------------------------------------------------------------
// JSON helpers
//------------------------------------------------------------------------------
static json_t jstr(const std::string &s)
{
  json_t j;
  j.type = json_t::JSTR;
  j.s = s;
  return j;
}

static json_t jbool(bool b)
{
  json_t j;
  j.type = json_t::JBOOL;
  j.b = b;
  return j;
}

static json_t jnum(double v, const std::string &text)
{
  json_t j;
  j.type = json_t::JNUM;
  j.num = v;
  j.s = text;
  return j;
}

static json_t jint(int64 v)
{
  return jnum(double(v), strfmt("%" FMT_64 "d", v));
}

static json_t jobject()
{
  json_t j;
  j.type = json_t::JOBJECT;
  return j;
}

static json_t jarray()
{
  json_t j;
  j.type = json_t::JARRAY;
  return j;
}

static json_t jarr_str(const std::vector<std::string> &v)
{
  json_t j = jarray();
  for ( const auto &s : v )
    j.arr.push_back(jstr(s));
  return j;
}

static void put(json_t *o, const char *key, const json_t &v)
{
  for ( auto &kv : o->obj )
  {
    if ( kv.first == key )
    {
      kv.second = v;
      return;
    }
  }
  o->obj.push_back({ key, v });
}

static std::vector<std::string> str_list(const json_t *j)
{
  std::vector<std::string> out;
  if ( j != nullptr && j->is_arr() )
    for ( const auto &x : j->arr )
      out.push_back(x.as_text());
  return out;
}

static bool bool_of(const json_t *j, const char *key)
{
  const json_t *v = j != nullptr ? j->get(key) : nullptr;
  return v != nullptr && v->type == json_t::JBOOL && v->b;
}

static std::string error_response(const std::string &err)
{
  json_t r = jobject();
  put(&r, "ok", jbool(false));
  put(&r, "error", jstr(err));
  return r.dump();
}

// "0x180001000", "180001000": false if not an hexadecimal number
static bool parse_hex(const std::string &str, uint64 *out)
{
  std::string s = trim(str);
  if ( s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') )
    s = s.substr(2);
  if ( s.empty() || s.size() > 16 )
    return false;
  for ( char c : s )
    if ( isxdigit((unsigned char)c) == 0 )
      return false;
  *out = strtoull(s.c_str(), nullptr, 16);
  return true;
}

//------------------------------------------------------------------------------
// version B: the listing built from the request (Diaphora's exported data)
//------------------------------------------------------------------------------
struct side_b_t
{
  std::string name;
  std::string text;                   // the sections for the prompt
  std::set<uint64> addresses;         // the instructions of its listing
  size_t ninsns = 0;
  std::string key;                    // what identifies it in the cache
};

static std::string listing_line(uint64 ea, const std::string &text, const std::string &comment)
{
  std::string line = "  " + strfmt("%" FMT_64 "x", ea) + "  " + trim(text);
  std::string cmt = one_line(trim(comment), 200);
  if ( !cmt.empty() )
  {
    if ( int(line.size()) < FACTS_COLUMN )
      line.append(FACTS_COLUMN - line.size(), ' ');
    line += " ; " + cmt;
  }
  return line;
}

static bool build_side_b(const json_t &b, size_t budget, side_b_t *out, std::string *err)
{
  if ( !b.is_obj() )
  {
    *err = "the request has no version B";
    return false;
  }
  out->name = b.str("name");
  std::string demangled = b.str("demangled");
  std::string source = b.str("source");

  // blocks, sorted by address; their number is their position
  struct block_t
  {
    uint64 ea = 0;
    std::vector<uint64> succs;
    const json_t *lines = nullptr;
  };
  std::vector<block_t> blocks;
  const json_t *jb = b.get("blocks");
  if ( jb != nullptr && jb->is_arr() )
  {
    for ( const auto &x : jb->arr )
    {
      block_t blk;
      if ( !x.is_obj() || !parse_hex(x.str("address"), &blk.ea) )
        continue;
      const json_t *s = x.get("succs");
      if ( s != nullptr && s->is_arr() )
        for ( const auto &v : s->arr )
        {
          uint64 t;
          if ( parse_hex(v.as_text(), &t) )
            blk.succs.push_back(t);
        }
      blk.lines = x.get("lines");
      blocks.push_back(blk);
    }
  }
  std::sort(blocks.begin(), blocks.end(), [](const block_t &x, const block_t &y) { return x.ea < y.ea; });
  std::map<uint64, size_t> number;
  for ( size_t i = 0; i < blocks.size(); i++ )
    number[blocks[i].ea] = i;
  bool blocks_known = !bool_of(&b, "no_blocks");

  std::string listing;
  for ( const auto &blk : blocks )
  {
    if ( blocks_known )
    {
      std::string head = "block_" + strfmt("%" FMT_64 "x", blk.ea) + ":";
      if ( head.size() < 36 )
        head.append(36 - head.size(), ' ');
      std::string info = strfmt("block %u", unsigned(number[blk.ea]));
      if ( blk.succs.empty() )
        info += ", no successors (return or noreturn)";
      std::string succ;
      for ( uint64 t : blk.succs )
      {
        auto p = number.find(t);
        succ += (succ.empty() ? "" : ", ")
              + (p != number.end() ? strfmt("%u", unsigned(p->second)) : "outside " + hex_str(t));
      }
      if ( !succ.empty() )
        info += ", -> " + succ;
      listing += head + " ; " + info + "\n";
    }
    if ( blk.lines == nullptr || !blk.lines->is_arr() )
      continue;
    for ( const auto &l : blk.lines->arr )
    {
      uint64 ea;
      if ( !l.is_obj() || !parse_hex(l.str("address"), &ea) )
        continue;
      out->addresses.insert(ea);
      out->ninsns++;
      listing += listing_line(ea, l.str("text"), l.str("comment")) + "\n";
    }
  }
  if ( out->ninsns == 0 )
  {
    *err = "the request has no listing for version B";
    return false;
  }
  if ( out->ninsns > size_t(settings().max_insns) )
  {
    *err = strfmt("version B has %u instructions, more than the limit of %d (Claude-Rays Decompiler/Settings)",
                  unsigned(out->ninsns), settings().max_insns);
    return false;
  }

  std::string head = "== Function ==\n";
  head += "Name: " + out->name + "\n";
  if ( !demangled.empty() && demangled != out->name )
    head += "Demangled: " + demangled + "\n";
  uint64 addr;
  if ( parse_hex(b.str("address"), &addr) )
    head += "Address: " + hex_str(addr) + "\n";
  if ( !trim(b.str("prototype")).empty() )
    head += "Prototype: " + one_line(b.str("prototype"), 400) + " (from the exported database)\n";
  if ( !trim(b.str("comment")).empty() )
    head += "Comment: " + one_line(b.str("comment"), 300) + "\n";
  head += strfmt("Size: %u instructions", unsigned(out->ninsns));
  if ( blocks_known )
    head += strfmt(", %u basic blocks", unsigned(blocks.size()));
  head += "\n";
  head += "Source: " + (source.empty() ? std::string("another database") : source)
        + " (exported data only: no stack frame, types, data or call sites)\n\n";

  std::string listing_intro = blocks_known
    ? "== Listing ==\nDisassembly by basic block ('; ' text at the end of a line is an IDA comment).\n"
    : "== Listing ==\nDisassembly in address order: the basic blocks of this version were not exported.\n";
  std::string body = head + listing_intro + listing + "\n";
  if ( body.size() > budget )
  {
    *err = strfmt("the listing of version B (%u chars) does not fit in the context budget of %u chars "
                  "(Claude-Rays Decompiler/Settings)", unsigned(body.size()), unsigned(budget));
    return false;
  }

  // the calls are trimmed to the budget, never the listing
  std::vector<std::string> calls;
  const json_t *jc = b.get("calls");
  if ( jc != nullptr && jc->is_arr() )
  {
    for ( const auto &c : jc->arr )
    {
      if ( !c.is_obj() )
        continue;
      std::string proto = trim(c.str("prototype"));
      std::string name = c.str("name");
      std::string line = "  " + c.str("address") + "  " + (proto.empty() ? name : one_line(proto, 400));
      calls.push_back(line);
    }
  }
  std::string calls_text;
  size_t dropped = 0;
  for ( const auto &c : calls )
  {
    if ( body.size() + calls_text.size() + c.size() + 64 > budget )
    {
      dropped++;
      continue;
    }
    calls_text += c + "\n";
  }
  if ( !calls_text.empty() || dropped != 0 )
  {
    body += "== Called functions ==\n" + calls_text;
    if ( dropped != 0 )
      body += strfmt("(%u more left out for size)\n", unsigned(dropped));
    body += "\n";
  }
  std::vector<std::string> consts = str_list(b.get("constants"));
  if ( !consts.empty() )
  {
    std::string t = "== Constants ==\n  ";
    for ( size_t i = 0; i < consts.size(); i++ )
      t += (i == 0 ? "" : ", ") + one_line(consts[i], 120);
    t += "\n\n";
    if ( body.size() + t.size() <= budget )
      body += t;
  }
  out->text = body;

  // the cache key: the bytes hash exported by Diaphora, else the listing
  out->key = trim(b.str("bytes_hash"));
  if ( out->key.empty() )
  {
    uint64 h = 0xcbf29ce484222325ULL;
    for ( unsigned char c : out->text )
    {
      h ^= c;
      h *= 0x100000001b3ULL;
    }
    out->key = strfmt("listing:%016" FMT_64 "x", h);
  }
  return true;
}

//------------------------------------------------------------------------------
// the cache: netnode "$ clauderays diff", one blob per function of the open
// database, keyed by its start address
//------------------------------------------------------------------------------
static const char DIFF_NETNODE_NAME[] = "$ clauderays diff";
static const char DIFF_BLOB_TAG = 'D';
static const int DIFF_CACHE_VERSION = 1;

static bool diff_cache_load(ea_t func_ea, const std::string &a_hash, const std::string &b_key,
                            bool a_is_new, json_t *response)
{
  netnode node(DIFF_NETNODE_NAME, 0, false);
  if ( node == BADNODE )
    return false;
  bytevec_t blob;
  if ( node.getblob(&blob, nodeidx_t(func_ea), DIFF_BLOB_TAG) <= 0 || blob.empty() )
    return false;
  std::string text((const char *)blob.begin(), blob.size());
  while ( !text.empty() && text.back() == '\0' )
    text.pop_back();
  json_t j;
  if ( !json_parse(text, &j) || !j.is_obj() )
    return false;
  const json_t *r = j.get("response");
  // another pair, another orientation, or the bytes of A changed
  if ( r == nullptr || !r->is_obj() || j.str("a_bytes_hash") != a_hash || j.str("b_key") != b_key
    || bool_of(&j, "a_is_new") != a_is_new )
  {
    return false;
  }
  *response = *r;
  return true;
}

static void diff_cache_save(ea_t func_ea, const std::string &a_hash, const std::string &b_key,
                            bool a_is_new, const json_t &response)
{
  json_t j = jobject();
  put(&j, "version", jint(DIFF_CACHE_VERSION));
  put(&j, "a_bytes_hash", jstr(a_hash));
  put(&j, "b_key", jstr(b_key));
  put(&j, "a_is_new", jbool(a_is_new));
  put(&j, "response", response);
  std::string text = j.dump();
  netnode node(DIFF_NETNODE_NAME, 0, true);
  node.delblob(nodeidx_t(func_ea), DIFF_BLOB_TAG);
  if ( !node.setblob(text.data(), text.size(), nodeidx_t(func_ea), DIFF_BLOB_TAG) )
    log_error("could not save the diff of %s in the database", hex_str(func_ea).c_str());
}

//------------------------------------------------------------------------------
// the answer
//------------------------------------------------------------------------------
// one version of the answer, with its code shaped for the diff (annotations
// out, indentation rebuilt) and the address of each line
static json_t side_response(const decomp_result_t &res)
{
  json_t s = jobject();
  put(&s, "summary", jstr(res.summary));
  put(&s, "prototype", jstr(res.prototype));
  put(&s, "code", jstr(res.code));
  std::vector<std::string> lines;
  std::vector<ea_t> eas;
  shape_code(res.code, false, &lines, &eas);
  json_t jl = jarray();
  for ( size_t i = 0; i < lines.size(); i++ )
  {
    json_t l = jobject();
    put(&l, "text", jstr(lines[i]));
    put(&l, "address", jstr(i < eas.size() && eas[i] != BADADDR ? hex_str(eas[i]) : std::string()));
    jl.arr.push_back(l);
  }
  put(&s, "lines", jl);
  json_t u = jarray();
  for ( const auto &x : res.uncertain )
  {
    json_t o = jobject();
    put(&o, "address", jstr(x.address));
    put(&o, "reason", jstr(x.reason));
    u.arr.push_back(o);
  }
  put(&s, "uncertain", u);
  return s;
}

// the instruction at 'ea' belongs to the function of the open database
static bool in_function_a(func_t *pfn, uint64 ea)
{
  return func_contains(pfn, ea_t(ea)) && is_code(get_flags(ea_t(ea))) && get_item_head(ea_t(ea)) == ea_t(ea);
}

// a short list of addresses for a warning
static std::string address_list(const std::vector<std::string> &v)
{
  std::string out;
  for ( size_t i = 0; i < v.size() && i < 8; i++ )
    out += (i == 0 ? "" : ", ") + v[i];
  if ( v.size() > 8 )
    out += strfmt(" and %u more", unsigned(v.size() - 8));
  return out;
}

//------------------------------------------------------------------------------
std::string diff_functions(const std::string &request_json)
{
  if ( settings().claude_path.empty() )
    settings().load();
  json_t req;
  std::string err;
  if ( !json_parse(request_json, &req, &err) || !req.is_obj() )
    return error_response("the request is not valid JSON (" + err + ")");

  // version A: a function of the open database
  const json_t *ja = req.get("a");
  uint64 a_ea = 0;
  if ( ja == nullptr || !parse_hex(ja->str("ea"), &a_ea) )
    return error_response("the request has no address for version A");
  func_t *pfn = get_func(ea_t(a_ea));
  if ( pfn == nullptr )
    return error_response(hex_str(a_ea) + " is not a function of the open database");
  ea_t func_ea = pfn->start_ea;
  qstring qname;
  get_func_name(&qname, func_ea);
  std::string a_name = qname.empty() ? hex_str(func_ea) : qname.c_str();
  bool a_is_new = bool_of(&req, "a_is_new");
  bool force = bool_of(&req, "force");

  // version B: from the request
  const json_t *jb = req.get("b");
  side_b_t b;
  size_t budget = size_t(settings().budget);
  if ( !build_side_b(jb != nullptr ? *jb : json_t(), budget, &b, &err) )
    return error_response(err);

  std::string a_hash = func_bytes_hash(func_ea);
  if ( !force )
  {
    json_t cached;
    if ( diff_cache_load(func_ea, a_hash, b.key, a_is_new, &cached) )
    {
      log_info("%s: cached diff (%s, %s)", a_name.c_str(), cached.str("model").c_str(), cached.str("date").c_str());
      put(&cached, "cached", jbool(true));
      return cached.dump();
    }
  }

  show_wait_box("HIDECANCEL\nClaude-Rays Decompiler: collecting the context of %s...", a_name.c_str());
  collected_t col;
  bool ok = collect_function_context(func_ea, &col, budget);
  hide_wait_box();
  if ( !ok )
    return error_response(col.error);

  // the prompt: the assembly diff, then OLD and NEW
  std::string a_title = a_name + " (" + hex_str(func_ea) + "), from the open database";
  std::string b_title = b.name + ", from " + (jb->str("source").empty() ? std::string("the other database")
                                                                         : jb->str("source"));
  std::string prompt = strfmt("Compare the two versions of the function %s: decompile both, aligned, "
                              "then list and assess the changes. The open database is the %s version.\n\n",
                              a_name.c_str(), a_is_new ? "NEW" : "OLD");
  std::vector<std::string> hunks = str_list(req.get("asm_diff"));
  prompt += "== Assembly diff (OLD -> NEW, without addresses) ==\n";
  if ( hunks.empty() )
    prompt += "(the cleaned listings are equal: only addresses, registers or block order may differ)\n";
  for ( size_t i = 0; i < hunks.size() && i < MAX_ASM_DIFF_LINES; i++ )
    prompt += hunks[i] + "\n";
  if ( hunks.size() > MAX_ASM_DIFF_LINES )
    prompt += strfmt("(%u more lines left out for size)\n", unsigned(hunks.size() - MAX_ASM_DIFF_LINES));
  prompt += "\n";
  std::string part_a = col.body;
  std::string part_b = b.text;
  const std::string &old_part = a_is_new ? part_b : part_a;
  const std::string &new_part = a_is_new ? part_a : part_b;
  prompt += "######## OLD version: " + (a_is_new ? b_title : a_title) + " ########\n\n" + old_part;
  prompt += "######## NEW version: " + (a_is_new ? a_title : b_title) + " ########\n\n" + new_part;
  log_debug_text("diff input:", prompt);

  // the query, waiting in the wait box (Cancel kills it)
  const settings_t &s = settings();
  std::unique_ptr<job_t> job(new job_t);
  job->model = s.default_model;
  job->effort = effective_effort(job->model, s.effort);
  job->claude_path = s.claude_path;
  job->timeout = s.timeout;
  job->prompt = prompt;
  job->system_prompt = PAIR_SYSTEM_PROMPT;
  job->schema = PAIR_SCHEMA;
  std::string model_text = job->effort.empty() ? job->model : job->model + ", effort " + job->effort;
  log_info("comparing %s with %s (%u + %u instructions, %u chars of context) with %s...",
           a_name.c_str(), b.name.c_str(), unsigned(col.ninsns), unsigned(b.ninsns),
           unsigned(prompt.size()), model_text.c_str());
  uint64 started_ms = get_nsec_stamp() / 1000000;
  show_wait_box("NODELAY\nClaude is comparing the two versions of %s (%s)...\n"
                "This can take a while (it depends on the size of the two functions, the connection\n"
                "and Claude's own processing).", a_name.c_str(), model_text.c_str());
  job->thread = std::thread(run_job, job.get());
  bool cancelled = false;
  while ( !job->done )
  {
    if ( !cancelled && user_cancelled() )
    {
      cancelled = true;
      cancel_job(job.get());
      log_info("cancelling the diff of %s", a_name.c_str());
    }
    qsleep(WAIT_MS);
  }
  if ( job->thread.joinable() )
    job->thread.join();
  hide_wait_box();
  if ( cancelled )
    return error_response("cancelled");

  json_t inner;
  usage_t usage;
  if ( !job->ok )
    err = job->error;
  else
    extract_result(*job, &inner, &err, &usage);   // fills err on failure
  decomp_result_t res_old;
  decomp_result_t res_new;
  if ( err.empty() )
  {
    const json_t *jo = inner.get("old");
    const json_t *jn = inner.get("new");
    if ( jo == nullptr || jn == nullptr )
      err = safety_error(usage, &inner, "the answer has no old or new version");
    else if ( !decode_result(*jo, &res_old, &err) || !decode_result(*jn, &res_new, &err) )
      // the model explains a stop in the summary of a version
      err = safety_error(usage, jn->str("summary").empty() ? jo : jn, "error unpacking the answer (" + err + ")");
  }
  if ( !err.empty() )
  {
    log_error("comparing %s failed: %s", a_name.c_str(), err.c_str());
    return error_response(err);
  }
  if ( get_func(func_ea) == nullptr )
    return error_response(hex_str(func_ea) + " is no longer a function: the answer is dropped");

  // validation: version A against the database, version B against the
  // listing of the request, and the addresses of the changes
  std::vector<std::string> warnings;
  if ( usage.safety_stops > 0 )
    warnings.push_back(safety_note(usage.safety_stops, usage.models));
  const decomp_result_t &res_a = a_is_new ? res_new : res_old;
  const decomp_result_t &res_b = a_is_new ? res_old : res_new;
  const char *tag_a = a_is_new ? "new: " : "old: ";
  const char *tag_b = a_is_new ? "old: " : "new: ";
  for ( const auto &w : validate_result(func_ea, res_a) )
    warnings.push_back(tag_a + w);
  {
    std::vector<ea_t> notes = code_annotations(res_b.code);
    std::vector<std::string> bad;
    for ( ea_t ea : notes )
      if ( b.addresses.count(uint64(ea)) == 0 )
        bad.push_back(hex_str(ea));
    if ( notes.empty() )
      warnings.push_back(std::string(tag_b) + "the code has no address annotations");
    else if ( !bad.empty() )
      warnings.push_back(std::string(tag_b) + "annotations that are not instructions of its listing: "
                         + address_list(bad));
  }
  json_t changes = jarray();
  const json_t *jch = inner.get("changes");
  if ( jch != nullptr && jch->is_arr() )
  {
    int n = 0;
    for ( const auto &c : jch->arr )
    {
      if ( !c.is_obj() )
        continue;
      n++;
      changes.arr.push_back(c);
      for ( int side = 0; side < 2; side++ )
      {
        bool is_old = side == 0;
        bool is_a = is_old != a_is_new;
        std::vector<std::string> bad;
        for ( const auto &a : str_list(c.get(is_old ? "old_addresses" : "new_addresses")) )
        {
          uint64 ea;
          bool found = parse_hex(a, &ea) && (is_a ? in_function_a(pfn, ea) : b.addresses.count(ea) != 0);
          if ( !found )
            bad.push_back(a);
        }
        if ( !bad.empty() )
          warnings.push_back(strfmt("change %d: %s addresses not in the %s listing: ",
                                    n, is_old ? "old" : "new", is_old ? "OLD" : "NEW") + address_list(bad));
      }
    }
  }

  json_t r = jobject();
  put(&r, "ok", jbool(true));
  put(&r, "error", jstr(std::string()));
  put(&r, "old", side_response(res_old));
  put(&r, "new", side_response(res_new));
  put(&r, "changes", changes);
  const json_t *as = inner.get("assessment");
  put(&r, "assessment", as != nullptr && as->is_obj() ? *as : jobject());
  put(&r, "warnings", jarr_str(warnings));
  put(&r, "model", jstr(job->model));
  put(&r, "model_id", jstr(usage.model_id));
  put(&r, "effort", jstr(job->effort));
  put(&r, "date", jstr(now_str()));
  put(&r, "a_is_new", jbool(a_is_new));
  json_t u = jobject();
  put(&u, "input_tokens", jint(usage.input_tokens));
  put(&u, "output_tokens", jint(usage.output_tokens));
  put(&u, "cost_usd", jnum(usage.cost_usd, strfmt("%.6f", usage.cost_usd)));
  put(&r, "usage", u);
  put(&r, "cached", jbool(false));
  diff_cache_save(func_ea, a_hash, b.key, a_is_new, r);

  uint64 ms = get_nsec_stamp() / 1000000 - started_ms;
  log_info("%s compared by %s in %.1f s (%u change(s), %u warning(s), %" FMT_64 "d in / %" FMT_64 "d out tokens, "
           "$%.4f at API prices)",
           a_name.c_str(), usage.model_id.empty() ? job->model.c_str() : usage.model_id.c_str(),
           double(ms) / 1000.0, unsigned(changes.arr.size()), unsigned(warnings.size()),
           usage.input_tokens, usage.output_tokens, usage.cost_usd);
  for ( const auto &w : warnings )
    log_info("  warning: %s", w.c_str());
  return r.dump();
}

} // namespace clauderays
