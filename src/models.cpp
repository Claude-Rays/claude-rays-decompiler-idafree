// Claude-Rays Decompiler - built-in catalog of Claude models
#include "models.hpp"

#include <cstdio>

namespace clauderays
{

// Prices are the Anthropic API rates (what the CLI reports as total_cost_usd);
// on a Claude subscription the queries count against the plan usage instead.
// Source: Anthropic model table of 2026-10-06. Keep the aliases first.
// Effort: reverse engineering needs precision, so never below medium: high on
// Haiku and Sonnet, medium on Opus and Fable (the Opus default of Claude Code).
// Haiku 4.5 has no effort control (nullptr: --effort is not passed).
static const std::vector<model_info_t> MODEL_CATALOG =
{
  { "opus",   "Latest Opus",   "Opus",   0, 0, 0, nullptr, "medium" },
  { "sonnet", "Latest Sonnet", "Sonnet", 0, 0, 0, nullptr, "high" },
  { "haiku",  "Latest Haiku",  "Haiku",  0, 0, 0, nullptr, "high" },
  { "claude-fable-5-1",  "Fable 5.1",  nullptr, 1000, 10.00, 50.00, nullptr, "medium" },
  { "claude-opus-5-5",   "Opus 5.5",   nullptr, 1000,  4.00, 20.00, nullptr, "medium" },
  { "claude-opus-5",     "Opus 5",     nullptr, 1000,  5.00, 25.00, nullptr, "medium" },
  { "claude-opus-4-8",   "Opus 4.8",   nullptr, 1000,  5.00, 25.00, nullptr, "medium" },
  { "claude-sonnet-5-5", "Sonnet 5.5", nullptr, 1000,  2.00, 10.00, nullptr, "high" },
  { "claude-sonnet-5",   "Sonnet 5",   nullptr, 1000,  2.00, 10.00, nullptr, "high" },
  { "claude-sonnet-4-6", "Sonnet 4.6", nullptr, 1000,  3.00, 15.00, nullptr, "high" },
  { "claude-haiku-5-5",  "Haiku 5.5",  nullptr, 1000,  0.10,  0.50, "up to 100K input tokens", "high" },
  { "claude-haiku-4-5",  "Haiku 4.5",  nullptr,  200,  1.00,  5.00, nullptr, nullptr },
};

const char *const EFFORT_LEVELS[5] = { "low", "medium", "high", "xhigh", "max" };

std::string effective_effort(const std::string &model, const std::string &setting)
{
  if ( !setting.empty() && setting != "auto" )
    return setting;
  const model_info_t *m = find_model_info(model);
  return m != nullptr && m->effort != nullptr ? m->effort : "";
}

const std::vector<model_info_t> &model_catalog()
{
  return MODEL_CATALOG;
}

const model_info_t *find_model_info(const std::string &id)
{
  for ( const auto &m : MODEL_CATALOG )
    if ( id == m.id )
      return &m;
  return nullptr;
}

// "$4", "$0.10"
static std::string price_str(double usd)
{
  char buf[32];
  if ( usd < 1.0 )
    snprintf(buf, sizeof(buf), "$%.2f", usd);
  else
    snprintf(buf, sizeof(buf), "$%g", usd);
  return buf;
}

static std::string prices_str(const model_info_t &m)
{
  std::string s = price_str(m.in_price) + " in, " + price_str(m.out_price) + " out per MTok";
  if ( m.note != nullptr )
    s += std::string(" (") + m.note + ")";
  return s;
}

static std::string context_str(const model_info_t &m)
{
  char buf[32];
  if ( m.context_k >= 1000 && m.context_k % 1000 == 0 )
    snprintf(buf, sizeof(buf), "%dM context", m.context_k / 1000);
  else
    snprintf(buf, sizeof(buf), "%dK context", m.context_k);
  return buf;
}

std::string model_menu_label(const std::string &id)
{
  const model_info_t *m = find_model_info(id);
  if ( m == nullptr )
    return id;
  if ( m->alias_of != nullptr )
    return std::string(m->name) + " (" + m->id + ")";
  return std::string(m->name) + " (" + price_str(m->in_price) + " in, "
       + price_str(m->out_price) + " out per MTok)";
}

std::string model_description(const std::string &id)
{
  const model_info_t *m = find_model_info(id);
  if ( m == nullptr )
    return id;
  std::string effort = m->effort != nullptr
                     ? std::string(", auto effort ") + m->effort
                     : std::string(", no effort control");
  if ( m->alias_of != nullptr )
    return std::string("alias, the newest ") + m->alias_of + " known by the installed CLI" + effort;
  return std::string(m->name) + ", " + context_str(*m) + ", " + prices_str(*m) + effort;
}

std::string model_combo_item(const std::string &id)
{
  if ( find_model_info(id) == nullptr )
    return id;
  std::string item = id;
  while ( item.size() < 20 )
    item += ' ';
  return item + " " + model_description(id);
}

std::string model_from_combo_item(const std::string &item)
{
  size_t b = item.find_first_not_of(" \t");
  if ( b == std::string::npos )
    return std::string();
  size_t e = item.find_first_of(" \t", b);
  return item.substr(b, e == std::string::npos ? std::string::npos : e - b);
}

} // namespace clauderays
