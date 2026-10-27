// Claude-Rays Decompiler - shared declarations
#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <string>
#include <vector>

#define CLAUDERAYS_VERSION "0.1.0-beta"

namespace clauderays
{

//------------------------------------------------------------------------------
// settings (persisted in IDA's registry, subkey "ClaudeRaysDecompiler")
//------------------------------------------------------------------------------
struct settings_t
{
  // model used by Decompile (opus by default: the most readable results;
  // sonnet is weaker and haiku falls short)
  std::string default_model;
  // model ids typed by the user that are not in the built-in catalog
  // (models.cpp); the menus offer the catalog plus these
  std::vector<std::string> models;
  // "claude --effort": auto (the model's default in the catalog) or a level
  std::string effort;
  // claude.exe: a name looked up in PATH or a full path
  std::string claude_path;
  // timeout for one answer, in seconds (0 = wait forever)
  int timeout = 0;
  // functions with more instructions are not sent
  int max_insns = 1500;
  // size budget of the collected context, in characters
  int budget = 60000;
  // shortcut of Claude-Rays Decompiler/Decompile
  std::string hotkey;
  // log debug messages (full input and output, section sizes, usage)
  bool verbose = false;
  // show the /*0x...*/ address annotations in the view (hidden by default:
  // double click still uses them)
  bool show_annotations = false;

  void load();
  void save() const;
  std::string models_str() const;
  // the catalog models are dropped from the list
  void set_models(const std::string &csv);
  // "" selects the default (opus)
  void set_default_model(const std::string &name);
  // what the menus offer: the catalog, then the extra models
  std::vector<std::string> menu_models() const;
};

settings_t &settings();

//------------------------------------------------------------------------------
// logging (output goes to IDA's output window)
//------------------------------------------------------------------------------
void log_info(const char *fmt, ...) AS_PRINTF(1, 2);
void log_error(const char *fmt, ...) AS_PRINTF(1, 2);
void log_debug(const char *fmt, ...) AS_PRINTF(1, 2);
// multi line text, printed only in verbose mode
void log_debug_text(const char *title, const std::string &text);

//------------------------------------------------------------------------------
// small helpers
//------------------------------------------------------------------------------
std::string strfmt(const char *fmt, ...) AS_PRINTF(1, 2);
// 0x prefix, lowercase digits
std::string hex_str(uint64 v);
// no prefix, lowercase digits (the listing format)
std::string addr_str(ea_t ea);
std::string trim(const std::string &s);
std::string tag_removed(const qstring &line);
// one line, at most 'max' bytes (cut on an UTF-8 boundary)
std::string one_line(const std::string &s, size_t max);
std::vector<std::string> split_lines(const std::string &s);
// name of 'ea' ("" if none)
std::string ea_name(ea_t ea);
// "0x401000", "401000h", "401000" or a name; BADADDR if it does not resolve
ea_t parse_address(const std::string &s);
// current local time, "2026-10-16 13:24"
std::string now_str();

} // namespace clauderays
