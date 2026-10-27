// Claude-Rays Decompiler - Decompile, analyze and patch
#include "fixes.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>

namespace clauderays
{

//------------------------------------------------------------------------------
// the fix query: a second query with the decompiled code (with line numbers)
// and the findings, so the analysis keeps its own prompt and schema
//------------------------------------------------------------------------------
static const char FIX_PROMPT[] =
  "You are a security engineer. The user message gives ONE function "
  "decompiled into C from a binary by a plugin, with numbered lines, and the "
  "security findings of an earlier review of it, each with its number. For "
  "each finding, propose the smallest fix of this C code that removes the "
  "bug, as edits of its lines. The fix is a suggestion for the analyst, "
  "shown as a patch of the decompiled code: it is not applied to the binary.\n"
  "\n"
  "The code lines may start with an address comment such as /*0x401020*/: "
  "the address of the instruction of that statement in the binary.\n"
  "\n"
  "Rules:\n"
  "- Minimal: change only what the fix of the finding needs. Keep the names, "
  "types, style and comments of the rest. No refactoring, no unrelated "
  "hardening, no fix for anything that is not a listed finding.\n"
  "- Use what the function has: its parameters, locals, globals and the "
  "constants of the code (the size of a local array, a length field). On an "
  "error, follow the convention the function already uses (its error return "
  "values, HRESULT, NTSTATUS, BOOL, errno, a cleanup label...).\n"
  "- When the fix needs something the function does not have (the real size "
  "of a buffer of the caller, a new parameter, a lock taken elsewhere) or "
  "belongs to another function, the finding is not fixable here: fixable "
  "false, and say in note what and where to fix.\n"
  "- Keep the /*0x...*/ address comment of a statement that you keep or "
  "rewrite in place; new statements have none.\n"
  "- Mark the first new or changed line of each fix with a trailing comment "
  "'// FIX <n>: <what it does>', n the number of the finding.\n"
  "\n"
  "Answer fields:\n"
  "- fixes: one entry per listed finding, with:\n"
  "  - finding: its number.\n"
  "  - fixable: true when the edits fix it.\n"
  "  - note: one or two sentences: what the fix does and what it assumes, or "
  "why it cannot be fixed in this function.\n"
  "  - edits: each replaces the lines first_line..last_line (inclusive, the "
  "numbers of the input) with 'lines', the new text, one string per line and "
  "without line numbers. To insert code, replace the line before or after it "
  "with the new lines plus that line unchanged. To delete lines, give an "
  "empty 'lines'. An edit is a whole sequence of statements with balanced "
  "braces: when the fix wraps existing code in a new block, the edit covers "
  "that code. The edits of all the fixes must not overlap: when two findings "
  "need the same lines, put the change in the fix of the lower number and "
  "leave the other with fixable true, no edits and a note that says which "
  "fix covers it. An empty array when fixable is false.\n"
  "Answer only with the structured output.";

// {fixes: [{finding, fixable, note, edits: [{first_line, last_line, lines}]}]}
static const char FIX_SCHEMA[] =
  "{\"type\":\"object\","
  "\"properties\":{"
    "\"fixes\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
      "\"properties\":{"
        "\"finding\":{\"type\":\"integer\"},"
        "\"fixable\":{\"type\":\"boolean\"},"
        "\"note\":{\"type\":\"string\"},"
        "\"edits\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
          "\"properties\":{"
            "\"first_line\":{\"type\":\"integer\"},"
            "\"last_line\":{\"type\":\"integer\"},"
            "\"lines\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},"
          "\"required\":[\"first_line\",\"last_line\",\"lines\"],\"additionalProperties\":false}}},"
      "\"required\":[\"finding\",\"fixable\",\"note\",\"edits\"],\"additionalProperties\":false}}},"
  "\"required\":[\"fixes\"],"
  "\"additionalProperties\":false}";

const char *fix_system_prompt()
{
  return FIX_PROMPT;
}

const char *fix_schema()
{
  return FIX_SCHEMA;
}

//------------------------------------------------------------------------------
// helpers (util.cpp needs IDA: these do not)
//------------------------------------------------------------------------------
static bool is_blank(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static std::string fx_trim(const std::string &s)
{
  size_t b = 0;
  size_t e = s.size();
  while ( b < e && is_blank(s[b]) )
    b++;
  while ( e > b && is_blank(s[e - 1]) )
    e--;
  return s.substr(b, e - b);
}

// the lines of 's' (a last empty line is not one), without '\r'
static std::vector<std::string> fx_split_lines(const std::string &s)
{
  std::vector<std::string> out;
  size_t start = 0;
  while ( start < s.size() )
  {
    size_t end = s.find('\n', start);
    if ( end == std::string::npos )
      end = s.size();
    std::string line = s.substr(start, end - start);
    if ( !line.empty() && line.back() == '\r' )
      line.pop_back();
    out.push_back(line);
    start = end + 1;
  }
  return out;
}

// 'line' without its /*0x...*/ annotations
static std::string fx_strip_annotations(const std::string &line)
{
  std::string out;
  size_t i = 0;
  while ( i < line.size() )
  {
    if ( line.compare(i, 4, "/*0x") == 0 )
    {
      size_t e = i + 4;
      while ( e < line.size() && isxdigit((unsigned char)line[e]) )
        e++;
      if ( e > i + 4 && e - (i + 4) <= 16 && line.compare(e, 2, "*/") == 0 )
      {
        i = e + 2;
        if ( i < line.size() && line[i] == ' ' )
          i++;
        continue;
      }
    }
    out += line[i++];
  }
  return out;
}

// the same statement: equal without the address comments and the blanks around
static bool same_line(const std::string &a, const std::string &b)
{
  return fx_trim(fx_strip_annotations(a)) == fx_trim(fx_strip_annotations(b));
}

static json_t jstr(const std::string &s)
{
  json_t j;
  j.type = json_t::JSTR;
  j.s = s;
  return j;
}

static json_t jnum(long long v)
{
  json_t j;
  j.type = json_t::JNUM;
  j.num = double(v);
  j.s = std::to_string(v);
  return j;
}

static json_t jbool(bool v)
{
  json_t j;
  j.type = json_t::JBOOL;
  j.b = v;
  return j;
}

// an integer member, -1 if missing or not a number
static int int_of(const json_t &o, const char *key)
{
  const json_t *v = o.get(key);
  return v != nullptr && v->type == json_t::JNUM ? int(v->num) : -1;
}

static bool bool_of(const json_t &o, const char *key)
{
  const json_t *v = o.get(key);
  return v != nullptr && v->type == json_t::JBOOL && v->b;
}

static double parse_double(const std::string &s)
{
  return s.empty() ? 0 : strtod(s.c_str(), nullptr);
}

//------------------------------------------------------------------------------
std::vector<fix_edit_t> fix_result_t::edits() const
{
  std::vector<fix_edit_t> out;
  for ( const auto &f : fixes )
    out.insert(out.end(), f.edits.begin(), f.edits.end());
  std::stable_sort(out.begin(), out.end(),
                   [] (const fix_edit_t &l, const fix_edit_t &r) { return l.first < r.first; });
  return out;
}

bool fix_result_t::has_edits() const
{
  for ( const auto &f : fixes )
    if ( !f.edits.empty() )
      return true;
  return false;
}

const fix_t *fix_result_t::fix_of(int finding) const
{
  for ( const auto &f : fixes )
    if ( f.finding == finding )
      return &f;
  return nullptr;
}

std::set<int> fix_wanted_numbers(const std::vector<int> &ranks)
{
  std::set<int> out;
  for ( size_t i = 0; i < ranks.size(); i++ )
    if ( ranks[i] <= 1 )
      out.insert(int(i + 1));
  return out;
}

std::string fix_prompt(const std::string &summary, const std::string &prototype, const std::string &code,
                       const std::vector<std::string> &texts, const std::set<int> &asked)
{
  std::string out;
  if ( !fx_trim(prototype).empty() )
    out += "== Function ==\n" + fx_trim(prototype) + "\n";
  if ( !fx_trim(summary).empty() )
    out += "== Summary ==\n" + fx_trim(summary) + "\n";
  out += "== Decompiled code (line numbers added) ==\n";
  std::vector<std::string> lines = fx_split_lines(code);
  int width = int(std::to_string(lines.size()).size());
  for ( size_t i = 0; i < lines.size(); i++ )
  {
    char num[32];
    snprintf(num, sizeof(num), "%*d| ", width, int(i + 1));
    out += num + lines[i] + "\n";
  }
  out += "== Findings to fix ==\n";
  for ( int n : asked )
    if ( n >= 1 && size_t(n) <= texts.size() )
      out += "Finding " + std::to_string(n) + ": " + texts[n - 1] + "\n";
  out += "\nGive one entry of 'fixes' per finding listed.\n";
  return out;
}

// the lines of an edit: a string with line ends counts as several lines
static std::vector<std::string> edit_lines(const json_t &e)
{
  std::vector<std::string> out;
  const json_t *a = e.get("lines");
  if ( a == nullptr || !a->is_arr() )
    return out;
  for ( const auto &x : a->arr )
  {
    std::string s;
    for ( char c : x.as_text() )
      if ( c != '\r' )
        s += c;
    if ( s.empty() )
    {
      out.push_back(std::string());
      continue;
    }
    for ( const auto &l : fx_split_lines(s) )
      out.push_back(l);
  }
  return out;
}

static std::string fmt_range_warning(int finding, int first, int last, size_t n)
{
  char buf[200];
  snprintf(buf, sizeof(buf), "edit of finding %d dropped: lines %d-%d are not lines of the code (1-%d)",
           finding, first, last, int(n));
  return buf;
}

std::vector<fix_t> decode_fixes(const json_t &answer, const std::vector<std::string> &code,
                                const std::set<int> &asked, std::vector<std::string> *warnings)
{
  std::map<int, const json_t *> by_finding;
  const json_t *a = answer.get("fixes");
  if ( a != nullptr && a->is_arr() )
  {
    for ( const auto &x : a->arr )
    {
      if ( !x.is_obj() )
        continue;
      int n = int_of(x, "finding");
      if ( asked.count(n) == 0 )
        warnings->push_back("fix of finding " + std::to_string(n) + " dropped: that finding was not asked for");
      else if ( by_finding.count(n) != 0 )
        warnings->push_back("second fix of finding " + std::to_string(n) + " dropped");
      else
        by_finding[n] = &x;
    }
  }
  // every edit of the fixable findings, checked against the code
  std::vector<fix_edit_t> all;
  for ( const auto &kv : by_finding )
  {
    const json_t &o = *kv.second;
    if ( !bool_of(o, "fixable") )
      continue;
    const json_t *edits = o.get("edits");
    if ( edits == nullptr || !edits->is_arr() )
      continue;
    for ( const auto &e : edits->arr )
    {
      if ( !e.is_obj() )
        continue;
      int first = int_of(e, "first_line");
      int last = int_of(e, "last_line");
      // last = first - 1: an insertion before line 'first' (after the trimming below, or from the cache)
      if ( first < 1 || last < first - 1 || size_t(last) > code.size() )
      {
        warnings->push_back(fmt_range_warning(kv.first, first, last, code.size()));
        continue;
      }
      // the lines kept at both ends are not part of the edit: they keep their address comment
      std::vector<std::string> lines = edit_lines(e);
      while ( first <= last && !lines.empty() && same_line(code[first - 1], lines.front()) )
      {
        first++;
        lines.erase(lines.begin());
      }
      while ( first <= last && !lines.empty() && same_line(code[last - 1], lines.back()) )
      {
        last--;
        lines.pop_back();
      }
      if ( first > last && lines.empty() )
        continue;
      fix_edit_t fe;
      fe.finding = kv.first;
      fe.first = first;
      fe.last = last;
      fe.lines = lines;
      all.push_back(fe);
    }
  }
  std::stable_sort(all.begin(), all.end(), [] (const fix_edit_t &l, const fix_edit_t &r)
  {
    return l.first != r.first ? l.first < r.first : l.finding < r.finding;
  });
  std::vector<fix_edit_t> kept;
  for ( const auto &e : all )
  {
    if ( !kept.empty() && e.first <= kept.back().last )
    {
      const fix_edit_t &prev = kept.back();
      char buf[300];
      snprintf(buf, sizeof(buf), "edit of finding %d dropped: lines %d-%d overlap the edit of finding %d "
               "(lines %d-%d)", e.finding, e.first, e.last, prev.finding, prev.first, prev.last);
      warnings->push_back(buf);
      continue;
    }
    kept.push_back(e);
  }
  std::vector<fix_t> out;
  for ( int n : asked )
  {
    auto p = by_finding.find(n);
    fix_t f;
    f.finding = n;
    if ( p == by_finding.end() )
    {
      warnings->push_back("the model gave no fix for finding " + std::to_string(n));
      f.note = "No answer for this finding.";
      out.push_back(f);
      continue;
    }
    const json_t &o = *p->second;
    f.note = fx_trim(o.str("note"));
    f.fixable = bool_of(o, "fixable");
    std::vector<fix_edit_t> mine;
    for ( const auto &e : kept )
      if ( e.finding == n )
        mine.push_back(e);
    const json_t *given = o.get("edits");
    if ( f.fixable && mine.empty() && given != nullptr && given->is_arr() && !given->arr.empty() )
    {
      warnings->push_back("fix of finding " + std::to_string(n) + " dropped: none of its edits could be applied");
      f.fixable = false;
    }
    if ( f.fixable )
      f.edits = mine;
    out.push_back(f);
  }
  return out;
}

//------------------------------------------------------------------------------
// the fixed code, side by side and as a unified diff
//------------------------------------------------------------------------------
std::vector<std::string> apply_fixes(const std::vector<std::string> &code, const std::vector<fix_edit_t> &edits)
{
  std::vector<std::string> out;
  size_t next = 1;
  for ( const auto &e : edits )
  {
    out.insert(out.end(), code.begin() + (next - 1), code.begin() + (e.first - 1));
    out.insert(out.end(), e.lines.begin(), e.lines.end());
    next = size_t(e.last) + 1;
  }
  out.insert(out.end(), code.begin() + std::min(next - 1, code.size()), code.end());
  return out;
}

std::vector<fix_row_t> fix_rows(int nlines, const std::vector<fix_edit_t> &edits)
{
  std::vector<fix_row_t> out;
  int i = 0;
  int j = 0;
  for ( const auto &e : edits )
  {
    for ( ; i < e.first - 1; i++, j++ )
      out.push_back({ i, j, 0 });
    int nold = e.last - e.first + 1;
    int nnew = int(e.lines.size());
    for ( int k = 0; k < std::max(nold, nnew); k++ )
      out.push_back({ k < nold ? i + k : -1, k < nnew ? j + k : -1, e.finding });
    i += nold;
    j += nnew;
  }
  for ( ; i < nlines; i++, j++ )
    out.push_back({ i, j, 0 });
  return out;
}

// an empty range names the line before it
static std::string unified_range(int start, int count)
{
  if ( count == 1 )
    return std::to_string(start + 1);
  return std::to_string(count == 0 ? start : start + 1) + "," + std::to_string(count);
}

std::vector<std::string> fix_unified_diff(const std::vector<std::string> &left, const std::vector<std::string> &right,
                                          const std::vector<fix_row_t> &rows, int context,
                                          const std::string &left_name, const std::string &right_name)
{
  std::vector<std::string> out;
  // the ranges of rows of each hunk: the changes with their context, merged
  std::vector<std::pair<int, int>> hunks;
  int nrows = int(rows.size());
  for ( int r = 0; r < nrows; r++ )
  {
    if ( !rows[r].changed() )
      continue;
    int s = std::max(r - context, 0);
    int e = r;
    while ( e + 1 < nrows && rows[e + 1].changed() )
      e++;
    int end = std::min(e + context + 1, nrows);
    if ( !hunks.empty() && s <= hunks.back().second )
      hunks.back().second = end;
    else
      hunks.push_back({ s, end });
    r = e;
  }
  if ( hunks.empty() )
    return out;
  out.push_back("--- " + left_name);
  out.push_back("+++ " + right_name);
  for ( const auto &h : hunks )
  {
    int old_start = 0;
    int new_start = 0;
    for ( int r = 0; r < h.first; r++ )
    {
      old_start += rows[r].left >= 0 ? 1 : 0;
      new_start += rows[r].right >= 0 ? 1 : 0;
    }
    int old_count = 0;
    int new_count = 0;
    std::set<int> findings;
    for ( int r = h.first; r < h.second; r++ )
    {
      old_count += rows[r].left >= 0 ? 1 : 0;
      new_count += rows[r].right >= 0 ? 1 : 0;
      if ( rows[r].changed() )
        findings.insert(rows[r].finding);
    }
    std::string names;
    for ( int n : findings )
      names += (names.empty() ? "F" : ", F") + std::to_string(n);
    out.push_back("@@ -" + unified_range(old_start, old_count) + " +" + unified_range(new_start, new_count)
                + " @@ " + names);
    for ( int r = h.first; r < h.second; )
    {
      if ( !rows[r].changed() )
      {
        out.push_back(" " + left[rows[r].left]);
        r++;
        continue;
      }
      // a block of changed rows: its old lines, then its new ones
      int e = r;
      while ( e < h.second && rows[e].changed() )
        e++;
      for ( int k = r; k < e; k++ )
        if ( rows[k].left >= 0 )
          out.push_back("-" + left[rows[k].left]);
      for ( int k = r; k < e; k++ )
        if ( rows[k].right >= 0 )
          out.push_back("+" + right[rows[k].right]);
      r = e;
    }
  }
  return out;
}

std::vector<std::string> wrap_text(const std::string &s, size_t width)
{
  std::vector<std::string> out;
  std::vector<std::string> paras = fx_split_lines(s);
  if ( paras.empty() )
    paras.push_back(std::string());
  for ( const auto &para : paras )
  {
    std::string line;
    size_t p = 0;
    while ( p <= para.size() )
    {
      size_t q = para.find(' ', p);
      if ( q == std::string::npos )
        q = para.size();
      std::string w = para.substr(p, q - p);
      p = q + 1;
      if ( w.empty() )
        continue;
      if ( !line.empty() && line.size() + 1 + w.size() > width )
      {
        out.push_back(line);
        line.clear();
      }
      if ( !line.empty() )
        line += ' ';
      line += w;
    }
    out.push_back(line);
  }
  return out;
}

//------------------------------------------------------------------------------
// cache
//------------------------------------------------------------------------------
json_t encode_fix_result(const fix_result_t &r)
{
  json_t j;
  j.type = json_t::JOBJECT;
  char cost[64];
  snprintf(cost, sizeof(cost), "%.6f", r.cost_usd);
  j.obj.push_back({ "model", jstr(r.model) });
  j.obj.push_back({ "model_id", jstr(r.model_id) });
  j.obj.push_back({ "effort", jstr(r.effort) });
  j.obj.push_back({ "date", jstr(r.date) });
  j.obj.push_back({ "cost_usd", jstr(cost) });
  j.obj.push_back({ "input_tokens", jstr(std::to_string(r.input_tokens)) });
  j.obj.push_back({ "output_tokens", jstr(std::to_string(r.output_tokens)) });
  j.obj.push_back({ "safety_stops", jstr(std::to_string(r.safety_stops)) });
  json_t models;
  models.type = json_t::JARRAY;
  for ( const auto &m : r.models )
    models.arr.push_back(jstr(m));
  j.obj.push_back({ "models", models });
  json_t fixes;
  fixes.type = json_t::JARRAY;
  for ( const auto &f : r.fixes )
  {
    json_t o;
    o.type = json_t::JOBJECT;
    o.obj.push_back({ "finding", jnum(f.finding) });
    o.obj.push_back({ "fixable", jbool(f.fixable) });
    o.obj.push_back({ "note", jstr(f.note) });
    json_t edits;
    edits.type = json_t::JARRAY;
    for ( const auto &e : f.edits )
    {
      json_t eo;
      eo.type = json_t::JOBJECT;
      eo.obj.push_back({ "first_line", jnum(e.first) });
      eo.obj.push_back({ "last_line", jnum(e.last) });
      json_t lines;
      lines.type = json_t::JARRAY;
      for ( const auto &l : e.lines )
        lines.arr.push_back(jstr(l));
      eo.obj.push_back({ "lines", lines });
      edits.arr.push_back(eo);
    }
    o.obj.push_back({ "edits", edits });
    fixes.arr.push_back(o);
  }
  j.obj.push_back({ "fixes", fixes });
  json_t w;
  w.type = json_t::JARRAY;
  for ( const auto &s : r.warnings )
    w.arr.push_back(jstr(s));
  j.obj.push_back({ "warnings", w });
  return j;
}

bool decode_cached_fix_result(const json_t *j, const std::vector<std::string> &code, int nfindings,
                              fix_result_t *out)
{
  if ( j == nullptr || !j->is_obj() )
    return false;
  *out = fix_result_t();
  out->model = j->str("model");
  out->model_id = j->str("model_id");
  out->effort = j->str("effort");
  out->date = j->str("date");
  out->cost_usd = parse_double(j->str("cost_usd"));
  out->input_tokens = (long long)parse_double(j->str("input_tokens"));
  out->output_tokens = (long long)parse_double(j->str("output_tokens"));
  out->safety_stops = int(parse_double(j->str("safety_stops")));
  const json_t *models = j->get("models");
  if ( models != nullptr && models->is_arr() )
    for ( const auto &m : models->arr )
      out->models.push_back(m.as_text());
  std::set<int> asked;
  const json_t *a = j->get("fixes");
  if ( a != nullptr && a->is_arr() )
    for ( const auto &x : a->arr )
    {
      int n = x.is_obj() ? int_of(x, "finding") : -1;
      if ( n >= 1 && n <= nfindings )
        asked.insert(n);
    }
  std::vector<std::string> ignored;
  out->fixes = decode_fixes(*j, code, asked, &ignored);
  const json_t *w = j->get("warnings");
  if ( w != nullptr && w->is_arr() )
    for ( const auto &x : w->arr )
      out->warnings.push_back(x.as_text());
  return true;
}

} // namespace clauderays
