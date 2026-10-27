// Claude-Rays Decompiler - results cached in the database
#include "cache.hpp"
#include "collector.hpp"
#include "json.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <netnode.hpp>

namespace clauderays
{

static const char NETNODE_NAME[] = "$ clauderays";
// the blob of each command; the versions with one result per function kept
// all of them in the one of Decompile
static const char BLOB_TAG = 'R';
static const char ANALYZE_BLOB_TAG = 'A';
static const char PATCH_BLOB_TAG = 'P';
static const int CACHE_VERSION = 1;

//------------------------------------------------------------------------------
// FNV-1a, 64 bits
struct fnv_t
{
  uint64 h = 0xcbf29ce484222325ULL;
  void add(const void *data, size_t n)
  {
    const uchar *p = static_cast<const uchar *>(data);
    for ( size_t i = 0; i < n; i++ )
    {
      h ^= p[i];
      h *= 0x100000001b3ULL;
    }
  }
  void add(const std::string &s) { add(s.data(), s.size() + 1); }
  std::string str() const { return strfmt("%016" FMT_64 "x", h); }
};

std::string func_bytes_hash(ea_t func_ea)
{
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr )
    return std::string();
  fnv_t h;
  func_tail_iterator_t fti(pfn);
  for ( bool ok = fti.main(); ok; ok = fti.next() )
  {
    const range_t &r = fti.chunk();
    uint64 bounds[2] = { uint64(r.start_ea), uint64(r.end_ea) };
    h.add(bounds, sizeof(bounds));
    bytevec_t buf;
    buf.resize(r.size());
    if ( r.size() > 0 && get_bytes(buf.begin(), r.size(), r.start_ea) > 0 )
      h.add(buf.begin(), buf.size());
  }
  return h.str();
}

std::string func_names_hash(ea_t func_ea)
{
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr )
    return std::string();
  fnv_t h;
  for ( ea_t ea : function_callees(pfn) )
    h.add(ea_name(ea));
  return h.str();
}

//------------------------------------------------------------------------------
static json_t jstr(const std::string &s)
{
  json_t j;
  j.type = json_t::JSTR;
  j.s = s;
  return j;
}

static json_t jarr_str(const std::vector<std::string> &v)
{
  json_t j;
  j.type = json_t::JARRAY;
  for ( const auto &s : v )
    j.arr.push_back(jstr(s));
  return j;
}

static std::vector<std::string> str_list(const json_t *j)
{
  std::vector<std::string> out;
  if ( j != nullptr && j->is_arr() )
    for ( const auto &x : j->arr )
      if ( x.is_str() )
        out.push_back(x.s);
  return out;
}

const char *cache_mode_key(cache_mode_t m)
{
  return m == CM_PATCH ? "patch" : m == CM_ANALYZE ? "analyze" : "decompile";
}

const char *cache_mode_label(cache_mode_t m)
{
  return m == CM_PATCH ? "Decompile, analyze and patch" : m == CM_ANALYZE ? "Decompile and analyze" : "Decompile";
}

static char blob_tag(cache_mode_t m)
{
  return m == CM_PATCH ? PATCH_BLOB_TAG : m == CM_ANALYZE ? ANALYZE_BLOB_TAG : BLOB_TAG;
}

static bool get_text(netnode node, ea_t func_ea, char tag, std::string *text)
{
  bytevec_t blob;
  if ( node.getblob(&blob, nodeidx_t(func_ea), tag) <= 0 || blob.empty() )
    return false;
  text->assign((const char *)blob.begin(), blob.size());
  while ( !text->empty() && text->back() == '\0' )
    text->pop_back();
  return true;
}

// A result of the versions with one result per function made by Decompile
// and analyze (or patch) goes to the blob of its command.
static void migrate(netnode node, ea_t func_ea)
{
  std::string text;
  // most results of Decompile are not parsed
  if ( !get_text(node, func_ea, BLOB_TAG, &text) || text.find("\"analyzed\"") == std::string::npos )
    return;
  json_t j;
  std::string err;
  if ( !json_parse(text, &j, &err) || !j.is_obj() )
    return;
  const json_t *an = j.get("analyzed");
  if ( an == nullptr || an->type != json_t::JBOOL || !an->b )
    return;
  char to = j.get("fix") != nullptr ? PATCH_BLOB_TAG : ANALYZE_BLOB_TAG;
  std::string old;
  if ( !get_text(node, func_ea, to, &old)
    && !node.setblob(text.data(), text.size(), nodeidx_t(func_ea), to) )
  {
    log_error("could not move the cached result of %s", hex_str(func_ea).c_str());
    return;
  }
  node.delblob(nodeidx_t(func_ea), BLOB_TAG);
}

cache_state_t cache_load(ea_t func_ea, cache_mode_t mode, cache_entry_t *out)
{
  netnode node(NETNODE_NAME, 0, false);
  if ( node == BADNODE )
    return CS_NONE;
  migrate(node, func_ea);
  std::string text;
  if ( !get_text(node, func_ea, blob_tag(mode), &text) )
    return CS_NONE;
  json_t j;
  std::string err;
  if ( !json_parse(text, &j, &err) || !j.is_obj() )
  {
    log_error("the cached result of %s cannot be read (%s): dropped", hex_str(func_ea).c_str(), err.c_str());
    cache_delete(func_ea, mode);
    return CS_NONE;
  }
  cache_entry_t e;
  e.bytes_hash = j.str("bytes_hash");
  e.names_hash = j.str("names_hash");
  e.model = j.str("model");
  e.model_id = j.str("model_id");
  e.effort = j.str("effort");
  e.date = j.str("date");
  e.cost_usd = atof(j.str("cost_usd").c_str());
  e.input_tokens = _atoi64(j.str("input_tokens").c_str());
  e.output_tokens = _atoi64(j.str("output_tokens").c_str());
  e.summary = j.str("summary");
  e.prototype = j.str("prototype");
  e.code = j.str("code");
  e.rounds = atoi(j.str("rounds").c_str());
  const json_t *u = j.get("uncertain");
  if ( u != nullptr && u->is_arr() )
    for ( const auto &x : u->arr )
      if ( x.is_obj() )
        e.uncertain.push_back({ x.str("address"), x.str("reason") });
  e.warnings = str_list(j.get("warnings"));
  e.missing = str_list(j.get("missing"));
  e.safety_stops = atoi(j.str("safety_stops").c_str());
  e.models = str_list(j.get("models"));
  const json_t *an = j.get("analyzed");
  e.analyzed = an != nullptr && an->type == json_t::JBOOL && an->b;
  e.findings = decode_findings(j.get("findings"));
  e.has_fix = decode_cached_fix_result(j.get("fix"), split_lines(e.code), int(e.findings.size()), &e.fix);

  if ( e.bytes_hash != func_bytes_hash(func_ea) )
  {
    log_info("the bytes of %s changed since it was decompiled: the cached result is dropped",
             hex_str(func_ea).c_str());
    cache_delete(func_ea, mode);
    return CS_NONE;
  }
  *out = e;
  return e.names_hash == func_names_hash(func_ea) ? CS_VALID : CS_STALE;
}

static void drop_warnings(std::vector<std::string> *warnings, const char *prefix)
{
  size_t n = strlen(prefix);
  for ( size_t i = 0; i < warnings->size(); )
  {
    if ( (*warnings)[i].compare(0, n, prefix) == 0 )
      warnings->erase(warnings->begin() + i);
    else
      i++;
  }
}

cache_state_t cache_load_or_derive(ea_t func_ea, cache_mode_t mode, cache_entry_t *out)
{
  cache_state_t st = cache_load(func_ea, mode, out);
  std::vector<cache_mode_t> richer;
  if ( mode == CM_DECOMPILE )
    richer = { CM_ANALYZE, CM_PATCH };
  else if ( mode == CM_ANALYZE )
    richer = { CM_PATCH };
  for ( size_t i = 0; st == CS_NONE && i < richer.size(); i++ )
  {
    st = cache_load(func_ea, richer[i], out);
    if ( st == CS_NONE )
      continue;
    out->derived_from = int(richer[i]);
    out->has_fix = false;
    out->fix = fix_result_t();
    drop_warnings(&out->warnings, "the fixes could not be made");
    if ( mode == CM_DECOMPILE )
    {
      out->analyzed = false;
      out->findings.clear();
      drop_warnings(&out->warnings, "security finding dropped");
    }
  }
  return st;
}

std::string model_used_str(const cache_entry_t &e)
{
  std::string s = e.model;
  if ( !e.model_id.empty() && e.model_id != e.model )
    s += " -> " + e.model_id;
  if ( !e.effort.empty() )
    s += ", effort " + e.effort;
  return s;
}

void cache_save(ea_t func_ea, cache_mode_t mode, const cache_entry_t &e)
{
  json_t j;
  j.type = json_t::JOBJECT;
  json_t ver;
  ver.type = json_t::JNUM;
  ver.num = CACHE_VERSION;
  ver.s = strfmt("%d", CACHE_VERSION);
  j.obj.push_back({ "version", ver });
  j.obj.push_back({ "bytes_hash", jstr(e.bytes_hash) });
  j.obj.push_back({ "names_hash", jstr(e.names_hash) });
  j.obj.push_back({ "model", jstr(e.model) });
  j.obj.push_back({ "model_id", jstr(e.model_id) });
  j.obj.push_back({ "effort", jstr(e.effort) });
  j.obj.push_back({ "date", jstr(e.date) });
  j.obj.push_back({ "rounds", jstr(strfmt("%d", e.rounds)) });
  j.obj.push_back({ "cost_usd", jstr(strfmt("%.6f", e.cost_usd)) });
  j.obj.push_back({ "input_tokens", jstr(strfmt("%" FMT_64 "d", e.input_tokens)) });
  j.obj.push_back({ "output_tokens", jstr(strfmt("%" FMT_64 "d", e.output_tokens)) });
  j.obj.push_back({ "summary", jstr(e.summary) });
  j.obj.push_back({ "prototype", jstr(e.prototype) });
  j.obj.push_back({ "code", jstr(e.code) });
  json_t u;
  u.type = json_t::JARRAY;
  for ( const auto &x : e.uncertain )
  {
    json_t o;
    o.type = json_t::JOBJECT;
    o.obj.push_back({ "address", jstr(x.address) });
    o.obj.push_back({ "reason", jstr(x.reason) });
    u.arr.push_back(o);
  }
  j.obj.push_back({ "uncertain", u });
  j.obj.push_back({ "warnings", jarr_str(e.warnings) });
  j.obj.push_back({ "missing", jarr_str(e.missing) });
  if ( e.safety_stops > 0 )
    j.obj.push_back({ "safety_stops", jstr(strfmt("%d", e.safety_stops)) });
  j.obj.push_back({ "models", jarr_str(e.models) });
  if ( e.analyzed )
  {
    json_t an;
    an.type = json_t::JBOOL;
    an.b = true;
    j.obj.push_back({ "analyzed", an });
    j.obj.push_back({ "findings", encode_findings(e.findings) });
  }
  if ( e.has_fix )
    j.obj.push_back({ "fix", encode_fix_result(e.fix) });
  std::string text = j.dump();

  netnode node(NETNODE_NAME, 0, true);
  node.delblob(nodeidx_t(func_ea), blob_tag(mode));
  if ( !node.setblob(text.data(), text.size(), nodeidx_t(func_ea), blob_tag(mode)) )
    log_error("could not save the result of %s in the database", hex_str(func_ea).c_str());
}

void cache_delete(ea_t func_ea, cache_mode_t mode)
{
  netnode node(NETNODE_NAME, 0, false);
  if ( node != BADNODE )
    node.delblob(nodeidx_t(func_ea), blob_tag(mode));
}

} // namespace clauderays
