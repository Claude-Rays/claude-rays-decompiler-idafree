// Claude-Rays Decompiler - settings, logging and small helpers
#include "common.hpp"
#include "models.hpp"

#include <lines.hpp>
#include <name.hpp>
#include <registry.hpp>

#include <ctime>

namespace clauderays
{

static const char REG_SUBKEY[] = "ClaudeRaysDecompiler";
static const char DEFAULT_MODEL[] = "opus";
static const char DEFAULT_CLAUDE_PATH[] = "claude";
static const char DEFAULT_HOTKEY[] = "Ctrl+Shift+F5";

//------------------------------------------------------------------------------
// settings
//------------------------------------------------------------------------------
settings_t &settings()
{
  static settings_t s;
  return s;
}

void settings_t::load()
{
  qstring v;
  set_models(reg_read_string(&v, "models", REG_SUBKEY) ? v.c_str() : "");
  set_default_model(reg_read_string(&v, "default_model", REG_SUBKEY) ? v.c_str() : "");
  effort = reg_read_string(&v, "effort", REG_SUBKEY) && !v.empty() ? v.c_str() : "auto";
  claude_path = reg_read_string(&v, "claude_path", REG_SUBKEY) && !v.empty() ? v.c_str() : DEFAULT_CLAUDE_PATH;
  hotkey = reg_read_string(&v, "hotkey", REG_SUBKEY) && !v.empty() ? v.c_str() : DEFAULT_HOTKEY;
  timeout = qmax(reg_read_int("timeout", 300, REG_SUBKEY), 0);
  max_insns = qmax(reg_read_int("max_insns", 1500, REG_SUBKEY), 10);
  budget = qmax(reg_read_int("budget", 60000, REG_SUBKEY), 4000);
  verbose = reg_read_int("verbose", 0, REG_SUBKEY) != 0;
  show_annotations = reg_read_int("show_annotations", 0, REG_SUBKEY) != 0;
}

void settings_t::save() const
{
  reg_write_string("models", models_str().c_str(), REG_SUBKEY);
  reg_write_string("default_model", default_model.c_str(), REG_SUBKEY);
  reg_write_string("effort", effort.c_str(), REG_SUBKEY);
  reg_write_string("claude_path", claude_path.c_str(), REG_SUBKEY);
  reg_write_string("hotkey", hotkey.c_str(), REG_SUBKEY);
  reg_write_int("timeout", timeout, REG_SUBKEY);
  reg_write_int("max_insns", max_insns, REG_SUBKEY);
  reg_write_int("budget", budget, REG_SUBKEY);
  reg_write_int("verbose", verbose ? 1 : 0, REG_SUBKEY);
  reg_write_int("show_annotations", show_annotations ? 1 : 0, REG_SUBKEY);
}

std::string settings_t::models_str() const
{
  std::string out;
  for ( const auto &m : models )
  {
    if ( !out.empty() )
      out += ", ";
    out += m;
  }
  return out;
}

// comma separated list without blanks, duplicates or catalog models (older
// settings kept the aliases here: they are in the catalog now)
void settings_t::set_models(const std::string &csv)
{
  models.clear();
  size_t start = 0;
  while ( start <= csv.size() )
  {
    size_t end = csv.find(',', start);
    if ( end == std::string::npos )
      end = csv.size();
    std::string m = trim(csv.substr(start, end - start));
    bool dup = find_model_info(m) != nullptr;
    for ( const auto &x : models )
      dup |= x == m;
    if ( !m.empty() && !dup )
      models.push_back(m);
    start = end + 1;
  }
}

void settings_t::set_default_model(const std::string &name)
{
  default_model = trim(name);
  if ( default_model.empty() )
    default_model = DEFAULT_MODEL;
}

std::vector<std::string> settings_t::menu_models() const
{
  std::vector<std::string> out;
  for ( const auto &m : model_catalog() )
    out.push_back(m.id);
  out.insert(out.end(), models.begin(), models.end());
  if ( find_model_info(default_model) == nullptr )
  {
    bool found = false;
    for ( const auto &m : models )
      found |= m == default_model;
    if ( !found )
      out.push_back(default_model);
  }
  return out;
}

//------------------------------------------------------------------------------
// logging
//------------------------------------------------------------------------------
static void vlog(const char *level, const char *fmt, va_list va)
{
  qstring s;
  s.vsprnt(fmt, va);
  msg("Claude-Rays Decompiler: %s%s\n", level, s.c_str());
}

void log_info(const char *fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  vlog("", fmt, va);
  va_end(va);
}

void log_error(const char *fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  vlog("ERROR: ", fmt, va);
  va_end(va);
}

void log_debug(const char *fmt, ...)
{
  if ( !settings().verbose )
    return;
  va_list va;
  va_start(va, fmt);
  vlog("[debug] ", fmt, va);
  va_end(va);
}

void log_debug_text(const char *title, const std::string &text)
{
  if ( !settings().verbose )
    return;
  msg("Claude-Rays Decompiler: [debug] %s\n", title);
  // msg() has a limited internal buffer, print line by line
  for ( const auto &line : split_lines(text) )
    msg("%s\n", line.c_str());
}

//------------------------------------------------------------------------------
// helpers
//------------------------------------------------------------------------------
std::string strfmt(const char *fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  qstring s;
  s.vsprnt(fmt, va);
  va_end(va);
  return s.c_str();
}

std::string hex_str(uint64 v)
{
  return strfmt("0x%" FMT_64 "x", v);
}

std::string addr_str(ea_t ea)
{
  return strfmt("%" FMT_64 "x", uint64(ea));
}

std::string trim(const std::string &s)
{
  size_t b = s.find_first_not_of(" \t\r\n");
  if ( b == std::string::npos )
    return std::string();
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::string tag_removed(const qstring &line)
{
  qstring out;
  tag_remove(&out, line);
  return out.c_str();
}

std::string one_line(const std::string &s, size_t max)
{
  std::string out;
  for ( char c : s )
    out += c == '\n' || c == '\r' || c == '\t' ? ' ' : c;
  out = trim(out);
  if ( out.size() > max )
  {
    size_t n = max;
    while ( n > 0 && (static_cast<unsigned char>(out[n]) & 0xC0) == 0x80 )
      n--;
    out = out.substr(0, n) + "...";
  }
  return out;
}

std::vector<std::string> split_lines(const std::string &s)
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

std::string ea_name(ea_t ea)
{
  qstring n;
  get_name(&n, ea);
  return n.c_str();
}

ea_t parse_address(const std::string &str)
{
  std::string s = trim(str);
  if ( s.empty() )
    return BADADDR;
  std::string digits = s;
  if ( digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X') )
    digits = digits.substr(2);
  else if ( digits.size() > 1 && (digits.back() == 'h' || digits.back() == 'H') )
    digits.pop_back();
  bool hex = !digits.empty() && digits.size() <= 16;
  for ( char c : digits )
    hex &= isxdigit((unsigned char)c) != 0;
  if ( hex )
  {
    ea_t ea = ea_t(strtoull(digits.c_str(), nullptr, 16));
    if ( is_mapped(ea) )
      return ea;
  }
  ea_t ea = get_name_ea(BADADDR, s.c_str());
  return ea != BADADDR && is_mapped(ea) ? ea : BADADDR;
}

std::string now_str()
{
  time_t t = time(nullptr);
  struct tm lt;
  localtime_s(&lt, &t);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &lt);
  return buf;
}

} // namespace clauderays
