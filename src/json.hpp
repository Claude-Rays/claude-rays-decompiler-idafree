// Claude-Rays Decompiler - minimal JSON support
// Enough to decode the Claude Code CLI output and serialize the model answer.
#pragma once

#include <map>
#include <string>
#include <vector>

namespace clauderays
{

struct json_t
{
  enum type_t { JNULL, JBOOL, JNUM, JSTR, JARRAY, JOBJECT };
  type_t type = JNULL;
  bool b = false;
  double num = 0;
  std::string s;                    // JSTR (UTF-8), JNUM keeps its source text
  std::vector<json_t> arr;
  std::vector<std::pair<std::string, json_t>> obj;  // keeps the key order

  bool is_str() const { return type == JSTR; }
  bool is_obj() const { return type == JOBJECT; }
  bool is_arr() const { return type == JARRAY; }

  // object member lookup, nullptr if missing or not an object
  const json_t *get(const char *key) const;
  // string value of a member ("" if missing); numbers/bools are stringified
  std::string str(const char *key) const;
  // the value as text: strings as is, the rest serialized
  std::string as_text() const;
  std::string dump() const;
};

std::string json_quote(const std::string &s);
// parse 'text'; on failure returns false and fills *err
bool json_parse(const std::string &text, json_t *out, std::string *err = nullptr);

} // namespace clauderays
