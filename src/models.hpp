// Claude-Rays Decompiler - built-in catalog of Claude models
// The models offered in Settings and in the "Other model" menus, with their
// context window and API prices. Update MODEL_CATALOG in models.cpp when new
// models reach the Claude Code CLI.
#pragma once

#include <string>
#include <vector>

namespace clauderays
{

struct model_info_t
{
  const char *id;             // what goes to "claude --model"
  const char *name;           // display name
  const char *alias_of;       // aliases: the family resolved by the CLI, else nullptr
  int context_k;              // context window, in thousands of tokens
  double in_price;            // USD per million input tokens
  double out_price;           // USD per million output tokens
  const char *note;           // extra pricing remark or nullptr
  // "claude --effort" when the setting is auto, never below medium (reverse
  // engineering needs precision); nullptr = not passed
  const char *effort;
};

// the effort levels of "claude --effort"
extern const char *const EFFORT_LEVELS[5];

// the effort to pass for 'model': 'setting' unless it is "auto" (or empty),
// then the catalog default; "" = do not pass --effort
std::string effective_effort(const std::string &model, const std::string &setting);

const std::vector<model_info_t> &model_catalog();

// nullptr if 'id' is not in the catalog
const model_info_t *find_model_info(const std::string &id);

// short menu label: "Opus 5.5 ($4 in, $20 out per MTok)"; the id if unknown
std::string model_menu_label(const std::string &id);

// longer description for tooltips and the settings list:
// "Opus 5.5, 1M context, $4 in, $20 out per MTok"
std::string model_description(const std::string &id);

// settings combobox item: "claude-opus-5-5   Opus 5.5, 1M context, ..."
std::string model_combo_item(const std::string &id);

// the model id at the start of a combobox item (its first word)
std::string model_from_combo_item(const std::string &item);

} // namespace clauderays
