// Claude-Rays Decompiler - Decompile, analyze and patch
// The suggested fixes of the security findings, as edits of the lines of the
// decompiled code. The model only writes the lines that change; the fixed
// code, the rows of the side by side view and the unified diff are built here
// from the validated edits. The findings are numbered from 1 in the order of
// the result (the most severe first). No IDA dependency.
#pragma once

#include "json.hpp"

#include <set>
#include <string>
#include <vector>

namespace clauderays
{

// Lines first..last (1-based, inclusive) of the code replaced by 'lines', for
// finding 'finding'; last = first - 1 inserts 'lines' before line first.
struct fix_edit_t
{
  int finding = 0;
  int first = 0;
  int last = 0;
  std::vector<std::string> lines;
  bool operator==(const fix_edit_t &o) const
  {
    return finding == o.finding && first == o.first && last == o.last && lines == o.lines;
  }
};

// The fix of one finding (its number). Fixable without edits: covered by the
// fix of another one, or (as the model also answers) nothing to change; its
// note says which.
struct fix_t
{
  int finding = 0;
  bool fixable = false;
  std::string note;
  std::vector<fix_edit_t> edits;
  bool operator==(const fix_t &o) const
  {
    return finding == o.finding && fixable == o.fixable && note == o.note && edits == o.edits;
  }
};

// the answer of the fix query, as cached with the result
struct fix_result_t
{
  std::string model;
  std::string model_id;
  std::string effort;
  std::string date;
  double cost_usd = 0;
  long long input_tokens = 0;
  long long output_tokens = 0;
  int safety_stops = 0;                   // of the query, and every model that answered (usage_t)
  std::vector<std::string> models;
  std::vector<fix_t> fixes;               // by finding number
  std::vector<std::string> warnings;      // validation

  // all the edits, by line
  std::vector<fix_edit_t> edits() const;
  bool has_edits() const;
  const fix_t *fix_of(int finding) const;
};

// the system prompt and schema of the fix query
const char *fix_system_prompt();
const char *fix_schema();

// The numbers of the findings worth a fix, from their ranks (finding_t::rank()):
// confirmed and possible (a theoretical one has no bug to fix).
std::set<int> fix_wanted_numbers(const std::vector<int> &ranks);

// The user message: the code with line numbers and the findings worth a fix
// ('texts': finding_text() of every finding).
std::string fix_prompt(const std::string &summary, const std::string &prototype, const std::string &code,
                       const std::vector<std::string> &texts, const std::set<int> &asked);

// The validated fixes of an answer: only the findings asked for, once each;
// edits inside the code, not overlapping (the first one by line wins), the
// lines kept at both ends trimmed and the edits that leave the code as it was
// dropped. A fixable finding whose edits were all dropped is not fixable;
// every finding asked for has an entry.
std::vector<fix_t> decode_fixes(const json_t &answer, const std::vector<std::string> &code,
                                const std::set<int> &asked, std::vector<std::string> *warnings);

// the code with the edits applied (edits sorted, not overlapping)
std::vector<std::string> apply_fixes(const std::vector<std::string> &code, const std::vector<fix_edit_t> &edits);

// One row of the side by side view: the line of the code on the left and of
// the fixed code on the right (0-based, -1 for a blank filler), and the
// finding whose fix changed it (0 for an unchanged row).
struct fix_row_t
{
  int left = -1;
  int right = -1;
  int finding = 0;
  bool changed() const { return finding != 0; }
  bool operator==(const fix_row_t &o) const { return left == o.left && right == o.right && finding == o.finding; }
};

std::vector<fix_row_t> fix_rows(int nlines, const std::vector<fix_edit_t> &edits);

// The unified diff of 'left' and 'right' (the lines of the rows), with
// 'context' lines around the changes; each hunk header names its findings
// ("@@ -10,7 +10,9 @@ F1, F3").
std::vector<std::string> fix_unified_diff(const std::vector<std::string> &left, const std::vector<std::string> &right,
                                          const std::vector<fix_row_t> &rows, int context,
                                          const std::string &left_name, const std::string &right_name);

// 's' cut at the blanks into lines of at most 'width' characters
std::vector<std::string> wrap_text(const std::string &s, size_t width);

// cache
json_t encode_fix_result(const fix_result_t &r);
// a cached result, checked again against the code it patches; false if 'j' is not one
bool decode_cached_fix_result(const json_t *j, const std::vector<std::string> &code, int nfindings,
                              fix_result_t *out);

} // namespace clauderays
