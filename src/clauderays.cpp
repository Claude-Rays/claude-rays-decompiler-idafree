// Claude-Rays Decompiler - plugin entry point
// Decompile the current function with Claude from its disassembly: the
// context is collected in the main thread (collector.cpp), the query runs in
// a background thread (backend.cpp) while the wait box loop collects the
// answer, serves the need_more rounds, validates, caches and shows the result.
#include "common.hpp"
#include "backend.hpp"
#include "cache.hpp"
#include "collector.hpp"
#include "fixes.hpp"
#include "logo.hpp"
#include "models.hpp"
#include "validate.hpp"
#include "view.hpp"

#include <funcs.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <undo.hpp>

#include <map>
#include <memory>
#include <set>

namespace clauderays
{

static const int MAX_ROUNDS = 2;            // need_more rounds per decompilation
static const int WAIT_MS = 50;              // wait box loop step

struct clauderays_t;

//------------------------------------------------------------------------------
// actions
//------------------------------------------------------------------------------
enum action_kind_t
{
  AK_DECOMPILE,         // default model, cached result if any
  AK_DECOMPILE_MODEL,   // another model, ignores the cache (in a view: its command)
  AK_REGENERATE,        // default model, ignores the cache: the command of the view again
  AK_ANALYZE,           // Decompile and analyze: its cached result if any
  AK_PATCH,             // Decompile, analyze and patch: its cached result if any
  AK_GENERATE_PATCH,    // the fixes of a view as a unified diff (no query)
  AK_CLEAR_FINDINGS,    // the colors of the security findings out of the disassembly
  AK_COPY,
  AK_APPLY_COMMENT,
  AK_CANCEL,
  AK_SHOW_CONTEXT,
  AK_SETTINGS,
};

struct action_ah_t : public action_handler_t
{
  clauderays_t &plg;
  action_kind_t kind;
  std::string model;
  action_ah_t(clauderays_t &p, action_kind_t k, const std::string &m = std::string())
    : plg(p), kind(k), model(m) {}
  int idaapi activate(action_activation_ctx_t *ctx) override;
  action_state_t idaapi update(action_update_ctx_t *) override { return AST_ENABLE_ALWAYS; }
};

struct registered_action_t
{
  std::string name;
  std::string popup_path;
  bool in_code;                 // disassembly / pseudocode views
  bool in_view;                 // Claude-Rays Decompiler views
  bool needs_patch = false;     // only in a view with fixes
  std::unique_ptr<action_handler_t> handler;
};

//------------------------------------------------------------------------------
// one decompilation in progress (possibly over several rounds)
//------------------------------------------------------------------------------
struct request_t
{
  ea_t func_ea = BADADDR;
  std::string func_name;
  std::string model;
  std::string effort;                   // "" = the CLI default
  bool analyze = false;                 // Decompile and analyze: the security analysis too
  bool patch = false;                   // Decompile, analyze and patch: then the fixes, in a second query
  bool fixing = false;                  // the query in flight is the one of the fixes
  cache_entry_t entry;                  // ... of this result (cached)
  cache_state_t entry_state = CS_VALID;
  std::set<int> asked;                  // ... of these findings
  int round = 0;
  std::string base_prompt;
  std::string requested;                // context served by need_more rounds
  std::set<std::string> seen;           // requests already served
  std::vector<std::string> ignored;     // requests that could not be served
  std::unique_ptr<job_t> job;
  uint64 started_ms = 0;

  // the command: where the result is cached and shown
  cache_mode_t mode() const { return cache_mode_of(analyze, patch); }

  // "sonnet, effort medium"
  std::string model_text() const
  {
    std::string s = effort.empty() ? model : model + ", effort " + effort;
    return patch ? s + ", with security analysis and fixes" : analyze ? s + ", with security analysis" : s;
  }
  bool cancelled = false;               // by the user: no more rounds
  usage_t usage;                        // all rounds; model_id of the last one
};

//------------------------------------------------------------------------------
// the plugin (one instance per database)
//------------------------------------------------------------------------------
struct clauderays_t : public plugmod_t, public event_listener_t
{
  std::vector<registered_action_t> actions;
  std::vector<std::unique_ptr<request_t>> requests;
  const request_t *waitbox = nullptr;   // request that owns the wait box
  qtimer_t rebuild_timer = nullptr;     // pending rebuild of the actions
  qtimer_t open_timer = nullptr;        // pending double click on a function
  ea_t open_ea = BADADDR;

  clauderays_t();
  ~clauderays_t() override;

  bool idaapi run(size_t arg) override;
  ssize_t idaapi on_event(ssize_t code, va_list va) override;

  void add_action(const std::string &name, const std::string &label, const std::string &tooltip,
                  const std::string &popup, const char *hotkey, bool in_code, bool in_view,
                  action_kind_t kind, const std::string &model = std::string());
  void register_actions();
  void unregister_actions();
  void schedule_rebuild_actions();
  static int idaapi rebuild_cb(void *ud);
  static void open_function(ea_t func_ea);
  static int idaapi open_cb(void *ud);

  ea_t target_function(TWidget *widget) const;
  request_t *find_request(ea_t func_ea, cache_mode_t mode) const;
  void decompile(ea_t func_ea, const std::string &model, bool use_cache, cache_mode_t mode = CM_DECOMPILE);
  void start_fix(request_t &req);
  void finish_fix(request_t &req);
  void generate_patch(ea_t func_ea) const;
  void clear_findings(ea_t func_ea) const;
  void start_round(request_t &req);
  void cancel(ea_t func_ea, int mode);
  void copy_code(TWidget *widget) const;
  void apply_comment(ea_t func_ea, cache_mode_t mode) const;
  void show_context(ea_t func_ea) const;
  bool edit_settings();

  void show_progress(const request_t &req);
  void hide_progress(const request_t *req);
  void wait_requests();
  void poll_requests();
  void finish_round(request_t &req);
  void finalize(request_t &req, const decomp_result_t &res, const std::vector<std::string> &missing);
};

//------------------------------------------------------------------------------
int idaapi action_ah_t::activate(action_activation_ctx_t *ctx)
{
  TWidget *widget = ctx != nullptr ? ctx->widget : nullptr;
  switch ( kind )
  {
    case AK_DECOMPILE:
      plg.decompile(plg.target_function(widget), settings().default_model, true);
      break;
    case AK_DECOMPILE_MODEL:
      // a regeneration from a view runs its command again (outside a view: Decompile)
      plg.decompile(plg.target_function(widget), model, false, view_mode(widget));
      break;
    case AK_REGENERATE:
      plg.decompile(plg.target_function(widget), settings().default_model, false, view_mode(widget));
      break;
    case AK_ANALYZE:
      plg.decompile(plg.target_function(widget), settings().default_model, true, CM_ANALYZE);
      break;
    case AK_PATCH:
      plg.decompile(plg.target_function(widget), settings().default_model, true, CM_PATCH);
      break;
    case AK_GENERATE_PATCH:
      plg.generate_patch(plg.target_function(widget));
      break;
    case AK_CLEAR_FINDINGS:
      plg.clear_findings(plg.target_function(widget));
      break;
    case AK_APPLY_COMMENT:
      plg.apply_comment(plg.target_function(widget), view_mode(widget));
      break;
    case AK_COPY:
      plg.copy_code(widget);
      break;
    case AK_CANCEL:
      // in a view, its command; elsewhere, every command of the function
      plg.cancel(plg.target_function(widget), view_function(widget) != BADADDR ? int(view_mode(widget)) : -1);
      break;
    case AK_SHOW_CONTEXT:
      plg.show_context(plg.target_function(widget));
      break;
    case AK_SETTINGS:
      plg.edit_settings();
      break;
  }
  return 1;
}

//------------------------------------------------------------------------------
// the instance of the open database (one at a time in IDA)
static clauderays_t *g_plugin = nullptr;

clauderays_t::clauderays_t()
{
  g_plugin = this;
  register_actions();
  hook_event_listener(HT_UI, this);
  view_set_open_function(open_function);
}

clauderays_t::~clauderays_t()
{
  unhook_event_listener(HT_UI, this);
  view_set_open_function(nullptr);
  g_plugin = nullptr;
  if ( open_timer != nullptr )
  {
    unregister_timer(open_timer);
    open_timer = nullptr;
  }
  if ( rebuild_timer != nullptr )
  {
    unregister_timer(rebuild_timer);
    rebuild_timer = nullptr;
  }
  hide_progress(waitbox);
  // abort the queries in flight and wait for their threads: once the CLI
  // processes are killed the threads finish immediately
  for ( auto &r : requests )
    cancel_job(r->job.get());
  for ( auto &r : requests )
    if ( r->job->thread.joinable() )
      r->job->thread.join();
  requests.clear();
  view_close_all();
  unregister_actions();
  log_info("unloaded");
}

//------------------------------------------------------------------------------
void clauderays_t::add_action(
        const std::string &name,
        const std::string &label,
        const std::string &tooltip,
        const std::string &popup,
        const char *hotkey,
        bool in_code,
        bool in_view,
        action_kind_t kind,
        const std::string &model)
{
  registered_action_t a;
  a.name = name;
  a.popup_path = popup;
  a.in_code = in_code;
  a.in_view = in_view;
  a.handler.reset(new action_ah_t(*this, kind, model));
  action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
        name.c_str(), label.c_str(), a.handler.get(), this, hotkey, tooltip.c_str(), -1);
  if ( !register_action(desc) )
  {
    log_error("could not register the action %s", name.c_str());
    return;
  }
  actions.push_back(std::move(a));
}

void clauderays_t::register_actions()
{
  const settings_t &s = settings();
  // each command has its view and its cached result: one never shows or replaces the result of another
  add_action("clauderays:decompile", "Decompile",
             "Decompile the current function with Claude (" + s.default_model + "), or show its cached result",
             "Claude-Rays Decompiler/", s.hotkey.c_str(), true, true, AK_DECOMPILE);
  add_action("clauderays:analyze", "Decompile and analyze",
             "Decompile the current function and review it for security bugs in the same query ("
             + s.default_model + "), or show its cached result",
             "Claude-Rays Decompiler/", "Ctrl+Shift+F6", true, true, AK_ANALYZE);
  add_action("clauderays:patch", "Decompile, analyze and patch",
             "Decompile and analyze the current function, then ask for the fixes of its confirmed and possible "
             "findings (a second query) and show them side by side (" + s.default_model + "); or show its "
             "cached result (a cached Decompile and analyze only needs the fixes)",
             "Claude-Rays Decompiler/", "Ctrl+Shift+F7", true, true, AK_PATCH);
  add_action("clauderays:generate_patch", "Generate patch",
             "Show the fixes of this function as a unified diff of its decompiled code (nothing is queried)",
             "Claude-Rays Decompiler/", nullptr, false, true, AK_GENERATE_PATCH);
  actions.back().needs_patch = true;
  add_action("clauderays:regenerate", "Regenerate",
             "Run the command of this view again with " + s.default_model + ", ignoring (and replacing) its "
             "cached result; the results of the other commands stay",
             "Claude-Rays Decompiler/", nullptr, false, true, AK_REGENERATE);
  // the other models: decompile again with a stronger (or cheaper) model
  std::vector<std::string> menu = s.menu_models();
  for ( size_t i = 0; i < menu.size(); i++ )
  {
    const std::string &m = menu[i];
    if ( m == s.default_model )
      continue;
    std::string label = model_menu_label(m);
    std::string desc = m + " (" + model_description(m) + ")";
    add_action(strfmt("clauderays:model:%u", unsigned(i)), label,
               "Decompile the current function with " + desc + ", ignoring the cached result",
               "Claude-Rays Decompiler/Other model/", nullptr, true, false, AK_DECOMPILE_MODEL, m);
    add_action(strfmt("clauderays:regen_model:%u", unsigned(i)), label,
               "Run the command of this view again with " + desc + ", ignoring its cached result",
               "Claude-Rays Decompiler/Regenerate with other model/", nullptr, false, true, AK_DECOMPILE_MODEL, m);
  }
  add_action("clauderays:apply_comment", "Apply summary as function comment",
             "Write the summary of the result as the function comment in the database",
             "Claude-Rays Decompiler/", nullptr, false, true, AK_APPLY_COMMENT);
  add_action("clauderays:copy", "Copy code", "Copy the C code (of a patch view: the patch) to the clipboard",
             "Claude-Rays Decompiler/", nullptr, false, true, AK_COPY);
  add_action("clauderays:cancel", "Cancel",
             "Cancel the decompilation of this view (outside a view: every decompilation of this function)",
             "Claude-Rays Decompiler/", nullptr, true, true, AK_CANCEL);
  add_action("clauderays:clear_findings", "Clear security highlights",
             "Remove the colors of the security findings of this function from the disassembly",
             "Claude-Rays Decompiler/", nullptr, true, true, AK_CLEAR_FINDINGS);
  add_action("clauderays:show_context", "Show collected context",
             "Print the context that would be sent for the current function to the Output window (nothing is sent)",
             "Claude-Rays Decompiler/", nullptr, true, false, AK_SHOW_CONTEXT);
  add_action("clauderays:settings", "Settings...",
             "Claude path, models, timeout, limits, shortcut and verbose logging",
             "Claude-Rays Decompiler/", nullptr, true, true, AK_SETTINGS);
}

void clauderays_t::unregister_actions()
{
  for ( auto &a : actions )
    unregister_action(a.name.c_str());
  actions.clear();
}

// Settings runs inside the activation of one of our actions: unregistering
// it there destroys the handler IDA is still using (a crash). The menus are
// rebuilt from the event loop once the action is over.
void clauderays_t::schedule_rebuild_actions()
{
  if ( rebuild_timer == nullptr )
    rebuild_timer = register_timer(0, rebuild_cb, this);
}

int idaapi clauderays_t::rebuild_cb(void *ud)
{
  clauderays_t *self = static_cast<clauderays_t *>(ud);
  self->rebuild_timer = nullptr;
  self->unregister_actions();
  self->register_actions();
  return -1;    // one shot
}

// Double click on a function in a Claude-Rays Decompiler view: its Decompile view, from the cache
// or with a new query (the wait box can cancel it). Run from the event loop,
// out of the viewer callback.
void clauderays_t::open_function(ea_t func_ea)
{
  clauderays_t *self = g_plugin;
  if ( self == nullptr )
    return;
  self->open_ea = func_ea;
  if ( self->open_timer == nullptr )
    self->open_timer = register_timer(0, open_cb, self);
}

int idaapi clauderays_t::open_cb(void *ud)
{
  clauderays_t *self = static_cast<clauderays_t *>(ud);
  self->open_timer = nullptr;
  ea_t ea = self->open_ea;
  self->open_ea = BADADDR;
  if ( ea != BADADDR )
    self->decompile(ea, settings().default_model, true);
  return -1;    // one shot
}

//------------------------------------------------------------------------------
// add the actions to the right-click menu of the code views and of our views
ssize_t idaapi clauderays_t::on_event(ssize_t code, va_list va)
{
  // the views are saved with the desktop and restored when the database opens
  if ( code == ui_get_widget_config )
  {
    const TWidget *widget = va_arg(va, const TWidget *);
    jobj_t *cfg = va_arg(va, jobj_t *);
    view_get_config(widget, cfg);
    return 0;
  }
  if ( code == ui_create_desktop_widget )
  {
    const char *title = va_arg(va, const char *);
    const jobj_t *cfg = va_arg(va, const jobj_t *);
    return ssize_t(view_create_for_desktop(title, cfg));
  }
  // the backgrounds of the columns of a side by side view
  if ( code == ui_get_lines_rendering_info )
  {
    lines_rendering_output_t *out = va_arg(va, lines_rendering_output_t *);
    const TWidget *widget = va_arg(va, const TWidget *);
    const lines_rendering_input_t *info = va_arg(va, const lines_rendering_input_t *);
    view_rendering_info(out, widget, info);
    return 0;
  }
  // the findings of a line of our views
  if ( code == ui_get_custom_viewer_hint )
  {
    qstring *hint = va_arg(va, qstring *);
    TWidget *viewer = va_arg(va, TWidget *);
    place_t *place = va_arg(va, place_t *);
    int *important_lines = va_arg(va, int *);
    return view_hint(viewer, place, hint, important_lines) ? 1 : 0;
  }
  if ( code == ui_finish_populating_widget_popup )
  {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    int wt = get_widget_type(widget);
    bool is_view = view_function(widget) != BADADDR;
    bool is_code = wt == BWN_DISASM || wt == BWN_PSEUDOCODE;
    if ( is_view || is_code )
    {
      bool patched = is_view && view_patched(widget);
      for ( const auto &a : actions )
        if ( (is_view ? a.in_view : a.in_code) && (!a.needs_patch || patched) )
          attach_action_to_popup(widget, popup, a.name.c_str(), a.popup_path.c_str());
    }
    // a patch view: only its copy
    else if ( view_is_patch(widget) )
    {
      attach_action_to_popup(widget, popup, "clauderays:copy", "Claude-Rays Decompiler/");
    }
  }
  return 0;
}

//------------------------------------------------------------------------------
// Edit > Plugins > Claude-Rays Decompiler
bool idaapi clauderays_t::run(size_t)
{
  static const char form[] =
    "STARTITEM 0\n"
    "BUTTON YES* ~O~K\n"
    "BUTTON CANCEL Cancel\n"
    "Claude-Rays Decompiler\n\n"
    "Claude-Rays Decompiler for IDA Free/Pro " CLAUDERAYS_VERSION " by ClaudeMonkey (Claude-Rays/claude-rays-decompiler-idafree)\n"
    "Decompile the current function with Claude: Claude-Rays Decompiler/Decompile in the\n"
    "right-click menu of the disassembly view, or its shortcut.\n\n"
    "<~D~ecompile the current function:R>\n"
    "<Decompile and ~a~nalyze the current function:R>\n"
    "<Decompile, analyze and ~p~atch the current function:R>\n"
    "<~S~ettings...:R>>\n";
  ushort choice = 0;
  if ( ask_form(form, &choice) <= 0 )
    return true;
  if ( choice == 0 )
    decompile(target_function(nullptr), settings().default_model, true);
  else if ( choice == 1 )
    decompile(target_function(nullptr), settings().default_model, true, CM_ANALYZE);
  else if ( choice == 2 )
    decompile(target_function(nullptr), settings().default_model, true, CM_PATCH);
  else
    edit_settings();
  return true;
}

//------------------------------------------------------------------------------
bool clauderays_t::edit_settings()
{
  settings_t &s = settings();
  static const char form[] =
    "BUTTON YES* ~O~K\n"
    "BUTTON CANCEL Cancel\n"
    "Claude-Rays Decompiler Settings\n\n"
    "<#claude.exe, as a name looked up in PATH (and in USERPROFILE\\.local\\bin) or a full path#Claude ~p~ath :q:1023:60::>\n"
    "<#Model used by Decompile. opus by default (sonnet is weaker, haiku falls short to decompile). "
    "An alias follows the newest version known by the CLI, a full id pins one version. "
    "Prices are API rates; on a subscription the queries count against the plan usage#"
    "~D~efault model:b:1:80::>\n"
    "<#Model ids not in the list above, comma separated (new models the CLI accepts). "
    "The menus Claude-Rays Decompiler/Other model offer the list plus these#E~x~tra models  :q:1023:60::>\n"
    "<#Thinking effort passed to claude (--effort). auto uses the default of each model in the list above, "
    "high on Haiku and Sonnet, medium on Opus and Fable#~E~ffort :b:0:30::>\n"
    "<#Seconds to wait for one answer, 0 waits forever#~T~imeout (s) :D::10::>\n"
    "<#Functions with more instructions are not sent#Max ~i~nstructions :D::10::>\n"
    "<#Size budget of the collected context, in characters (about 4 per token)#Context ~b~udget (chars):D::10::>\n"
    "<#Shortcut of Claude-Rays Decompiler/Decompile, e.g. Ctrl+Shift+F5#S~h~ortcut :q:63:30::>\n"
    "<##Options##~V~erbose logging (full input and output, section sizes, usage, rounds):C>\n"
    "<Show the /*0x...*/ ~a~ddress annotations in the code:C>>\n";
  qstring claude_path(s.claude_path.c_str());
  qstrvec_t model_choices;
  for ( const auto &m : s.menu_models() )
    model_choices.push_back(model_combo_item(m).c_str());
  qstring default_model(model_combo_item(s.default_model).c_str());
  qstring models(s.models_str().c_str());
  qstrvec_t effort_choices;
  effort_choices.push_back("auto (per model)");
  for ( const char *e : EFFORT_LEVELS )
    effort_choices.push_back(e);
  // a read-only combobox takes the index of the item (int), not its text
  int effort = 0;
  for ( int i = 0; i < int(qnumber(EFFORT_LEVELS)); i++ )
    if ( s.effort == EFFORT_LEVELS[i] )
      effort = i + 1;
  sval_t timeout = s.timeout;
  sval_t max_insns = s.max_insns;
  sval_t budget = s.budget;
  qstring hotkey(s.hotkey.c_str());
  ushort opts = (s.verbose ? 1 : 0) | (s.show_annotations ? 2 : 0);
  if ( ask_form(form, &claude_path, &model_choices, &default_model, &models,
                &effort_choices, &effort, &timeout, &max_insns, &budget, &hotkey, &opts) <= 0 )
  {
    return false;
  }

  std::string old_menu = s.default_model + "|" + s.models_str() + "|" + s.hotkey;
  s.claude_path = trim(claude_path.c_str());
  if ( s.claude_path.empty() )
    s.claude_path = "claude";
  s.set_models(models.c_str());
  s.set_default_model(model_from_combo_item(default_model.c_str()));
  s.effort = effort >= 1 && effort <= int(qnumber(EFFORT_LEVELS)) ? EFFORT_LEVELS[effort - 1] : "auto";
  s.timeout = timeout < 0 ? 0 : int(timeout);
  s.max_insns = max_insns < 10 ? 10 : int(max_insns);
  s.budget = budget < 4000 ? 4000 : int(budget);
  s.hotkey = trim(hotkey.c_str());
  s.verbose = (opts & 1) != 0;
  bool old_annotations = s.show_annotations;
  s.show_annotations = (opts & 2) != 0;
  s.save();
  if ( s.show_annotations != old_annotations )
    view_refresh_all();
  if ( s.default_model + "|" + s.models_str() + "|" + s.hotkey != old_menu )
    schedule_rebuild_actions();
  log_info("settings saved: claude=%s default model=%s extra models=%s effort=%s timeout=%d max insns=%d budget=%d shortcut=%s",
           s.claude_path.c_str(), s.default_model.c_str(), s.models_str().c_str(), s.effort.c_str(), s.timeout,
           s.max_insns, s.budget, s.hotkey.c_str());
  return true;
}

//------------------------------------------------------------------------------
ea_t clauderays_t::target_function(TWidget *widget) const
{
  ea_t ea = widget != nullptr ? view_function(widget) : BADADDR;
  if ( ea == BADADDR )
  {
    func_t *pfn = get_func(get_screen_ea());
    ea = pfn != nullptr ? pfn->start_ea : BADADDR;
  }
  return ea;
}

request_t *clauderays_t::find_request(ea_t func_ea, cache_mode_t mode) const
{
  for ( const auto &r : requests )
    if ( r->func_ea == func_ea && r->mode() == mode )
      return r.get();
  return nullptr;
}

//------------------------------------------------------------------------------
// The numbers of the findings worth a fix (confirmed and possible).
static std::set<int> wanted_fixes(const std::vector<finding_t> &findings)
{
  std::vector<int> ranks;
  for ( const auto &f : findings )
    ranks.push_back(f.rank());
  return fix_wanted_numbers(ranks);
}

// Run the command 'mode' on the function, in its view and with its cached
// result: the result of another command is never shown nor replaced.
// Decompile, analyze and patch without a cached result of its own (or with
// one whose fixes failed) reuses the cached Decompile and analyze: only the
// fixes are queried.
void clauderays_t::decompile(ea_t func_ea, const std::string &model, bool use_cache, cache_mode_t mode)
{
  bool patch = mode == CM_PATCH;
  bool analyze = mode != CM_DECOMPILE;
  if ( func_ea == BADADDR )
  {
    log_error("the cursor is not in a function");
    return;
  }
  qstring qname;
  get_func_name(&qname, func_ea);
  std::string name = qname.c_str();
  if ( find_request(func_ea, mode) != nullptr )
  {
    log_info("%s is already being decompiled by %s (Claude-Rays Decompiler/Cancel to stop it)", name.c_str(),
             cache_mode_label(mode));
    return;
  }

  if ( use_cache )
  {
    cache_entry_t e;
    // a result of a more complete command does too
    cache_state_t st = cache_load_or_derive(func_ea, mode, &e);
    bool from_analyze = false;
    if ( st == CS_NONE && patch )
    {
      st = cache_load(func_ea, CM_ANALYZE, &e);
      from_analyze = st != CS_NONE;
      if ( from_analyze )
        log_info("%s: the cached result of Decompile and analyze (%s, %s) is fixed", name.c_str(),
                 model_used_str(e).c_str(), e.date.c_str());
    }
    // only the fixes are missing (a cached analysis with nothing to fix needs none)
    bool need_fixes = patch && !e.has_fix && !wanted_fixes(e.findings).empty();
    if ( st != CS_NONE && !need_fixes )
    {
      if ( from_analyze )
        cache_save(func_ea, mode, e);   // the analysis alone is the result
      else
        log_info("%s: cached result of %s (%s, %s)%s%s", name.c_str(), cache_mode_label(mode),
                 model_used_str(e).c_str(), e.date.c_str(),
                 e.derived_from >= 0 ? (std::string(", taken from ") + cache_mode_label(cache_mode_t(e.derived_from))
                                        + ": nothing queried").c_str() : "",
                 st == CS_STALE ? ", stale: the callee names changed" : "");
      if ( patch && !e.has_fix )
        log_info("%s: no confirmed or possible finding, nothing to fix", name.c_str());
      view_show_result(func_ea, mode, e, st);
      return;
    }
    if ( st != CS_NONE )
    {
      std::unique_ptr<request_t> req(new request_t);
      req->func_ea = func_ea;
      req->func_name = name;
      req->model = model;
      req->effort = effective_effort(model, settings().effort);
      req->analyze = true;
      req->patch = true;
      req->entry = e;
      req->entry_state = st;
      req->started_ms = get_nsec_stamp() / 1000000;
      request_t &r = *req;
      requests.push_back(std::move(req));
      start_fix(r);
      wait_requests();
      return;
    }
  }

  show_wait_box("HIDECANCEL\nClaude-Rays Decompiler: collecting the context of %s...", name.c_str());
  collected_t col;
  bool ok = collect_function_context(func_ea, &col);
  hide_wait_box();
  if ( !ok )
  {
    warning("Claude-Rays Decompiler: %s.", col.error.c_str());
    return;
  }
  log_debug_text("input:", col.text);

  std::unique_ptr<request_t> req(new request_t);
  req->func_ea = func_ea;
  req->func_name = name;
  req->model = model;
  req->effort = effective_effort(model, settings().effort);
  req->analyze = analyze;
  req->patch = patch;
  req->base_prompt = col.text;
  req->started_ms = get_nsec_stamp() / 1000000;
  request_t &r = *req;
  requests.push_back(std::move(req));
  log_info("decompiling %s (%u instructions, %u chars of context) with %s...",
           name.c_str(), unsigned(col.ninsns), unsigned(col.text.size()), r.model_text().c_str());
  start_round(r);
  wait_requests();
}

// The documented wait box pattern: stay here until the request is over,
// calling user_cancelled() (it also keeps the UI painted) between short
// sleeps. Waiting from the event loop with a timer instead hung IDA when the
// decompilation was started from a double click.
void clauderays_t::wait_requests()
{
  while ( !requests.empty() )
  {
    poll_requests();
    if ( !requests.empty() )
      qsleep(WAIT_MS);
  }
}

void clauderays_t::start_round(request_t &req)
{
  const settings_t &s = settings();
  req.job.reset(new job_t);
  job_t *job = req.job.get();
  job->model = req.model;
  job->effort = req.effort;
  job->claude_path = s.claude_path;
  job->timeout = s.timeout;
  if ( req.analyze )
  {
    job->system_prompt = analyze_system_prompt();
    job->schema = analyze_schema();
  }
  job->prompt = req.base_prompt;
  if ( !req.requested.empty() )
    job->prompt += "== Requested context ==\n" + req.requested;
  if ( !req.ignored.empty() )
  {
    job->prompt += "== Requests that could not be served ==\n";
    for ( const auto &i : req.ignored )
      job->prompt += "  " + i + "\n";
  }
  if ( req.round > 0 )
  {
    job->prompt += strfmt("\nThis is round %d of %d: ", req.round, MAX_ROUNDS);
    job->prompt += req.round >= MAX_ROUNDS
      ? "no more context can be requested, give your final answer with need_more empty.\n"
      : "ask for more context only if it is really needed.\n";
    log_debug_text(strfmt("requested context (round %d):", req.round).c_str(), req.requested);
  }

  std::vector<std::string> status;
  status.push_back(strfmt("Claude-Rays Decompiler: %s %s with %s...", req.analyze ? "decompiling and analyzing" : "decompiling",
                          req.func_name.c_str(), req.model_text().c_str()));
  if ( req.round > 0 )
    status.push_back(strfmt("Asking for more context (round %d/%d).", req.round, MAX_ROUNDS));
  status.push_back("It can take a while (it depends on the size of the function, the connection and "
                   "Claude's own processing). Cancel in the wait box stops it.");
  view_show_status(req.func_ea, req.mode(), status);
  show_progress(req);

  job->thread = std::thread(run_job, job);
}

// The wait box, with its Cancel button, tells the user that Claude is working.
// wait_requests() checks the button (user_cancelled) while the query runs.
void clauderays_t::show_progress(const request_t &req)
{
  std::string text = strfmt("Claude is generating the decompilation of %s (%s)...\n",
                            req.func_name.c_str(), req.model_text().c_str());
  if ( req.round > 0 )
    text += strfmt("The model asked for more context (round %d/%d).\n", req.round, MAX_ROUNDS);
  text += "This can take a while (it depends on the size of the function, the connection\n"
          "and Claude's own processing).";
  if ( waitbox == &req )
  {
    replace_wait_box("%s", text.c_str());
  }
  else if ( waitbox == nullptr )
  {
    show_wait_box("NODELAY\n%s", text.c_str());
    waitbox = &req;
  }
}

void clauderays_t::hide_progress(const request_t *req)
{
  if ( req == nullptr || waitbox != req )
    return;
  hide_wait_box();
  waitbox = nullptr;
}

// cancel the decompilation of the command 'mode' (a cache_mode_t; -1: of every command) of the function
void clauderays_t::cancel(ea_t func_ea, int mode)
{
  bool any = false;
  for ( cache_mode_t m : CACHE_MODES )
  {
    request_t *r = mode < 0 || mode == int(m) ? find_request(func_ea, m) : nullptr;
    if ( r == nullptr )
      continue;
    r->cancelled = true;
    cancel_job(r->job.get());
    any = true;
    log_info("cancelling %s of %s", cache_mode_label(m), r->func_name.c_str());
  }
  if ( !any )
    log_info("nothing to cancel");
}

//------------------------------------------------------------------------------
// the security findings in the disassembly
//------------------------------------------------------------------------------
// color (or clear) the instructions of the findings, the most severe color on each
static void color_findings(const std::vector<finding_t> &findings, bool set)
{
  std::map<ea_t, int> ranks;
  for ( const auto &f : findings )
    for ( const auto &s : f.addresses )
    {
      ea_t ea = parse_address(s);
      if ( ea == BADADDR )
        continue;
      auto p = ranks.find(ea);
      if ( p == ranks.end() || f.rank() < p->second )
        ranks[ea] = f.rank();
    }
  for ( const auto &r : ranks )
  {
    if ( set )
      set_item_color(r.first, finding_color(r.second));
    else
      del_item_color(r.first);
  }
  if ( !ranks.empty() )
    refresh_idaview_anyway();
}

void clauderays_t::clear_findings(ea_t func_ea) const
{
  if ( func_ea == BADADDR )
  {
    log_error("the cursor is not in a function");
    return;
  }
  // the findings of every command of the function
  std::vector<finding_t> all;
  for ( cache_mode_t m : CACHE_MODES )
  {
    cache_entry_t e;
    if ( cache_load(func_ea, m, &e) != CS_NONE )
      all.insert(all.end(), e.findings.begin(), e.findings.end());
  }
  if ( all.empty() )
  {
    log_info("%s has no security findings to clear", hex_str(func_ea).c_str());
    return;
  }
  color_findings(all, false);
  log_info("security highlights of %s cleared from the disassembly", hex_str(func_ea).c_str());
}

//------------------------------------------------------------------------------
void clauderays_t::copy_code(TWidget *widget) const
{
  std::string code = view_code(widget);
  if ( code.empty() )
  {
    log_info("there is no code to copy yet");
    return;
  }
  if ( set_clipboard_text(code) )
    log_info("code copied to the clipboard");
  else
    log_error("could not copy the code to the clipboard");
}

// the summary of the result, as the regular function comment
void clauderays_t::apply_comment(ea_t func_ea, cache_mode_t mode) const
{
  func_t *pfn = func_ea != BADADDR ? get_func(func_ea) : nullptr;
  if ( pfn == nullptr )
  {
    log_error("the view is not on a function");
    return;
  }
  cache_entry_t e;
  if ( cache_load_or_derive(func_ea, mode, &e) == CS_NONE || trim(e.summary).empty() )
  {
    log_info("there is no summary to apply (Claude-Rays Decompiler/Regenerate makes one)");
    return;
  }
  std::string summary = trim(e.summary);
  qstring old;
  if ( get_func_cmt(&old, pfn, false) > 0 && trim(old.c_str()) != summary
    && ask_yn(ASKBTN_NO,
              "HIDECANCEL\n"
              "The function already has a comment:\n\n%s\n\nReplace it with the summary of Claude-Rays Decompiler?",
              one_line(old.c_str(), 400).c_str()) != ASKBTN_YES )
  {
    return;
  }
  bytevec_t rec;
  rec.pack_ds("Claude-Rays Decompiler comment");
  rec.pack_ds("Claude-Rays Decompiler: apply summary as function comment");
  create_undo_point(rec.begin(), rec.size());
  if ( set_func_cmt(pfn, summary.c_str(), false) )
    log_info("summary applied as the comment of %s", hex_str(func_ea).c_str());
  else
    log_error("could not set the comment of %s", hex_str(func_ea).c_str());
}

// Show collected context: what the collector extracts, without sending it
void clauderays_t::show_context(ea_t func_ea) const
{
  if ( func_ea == BADADDR )
  {
    log_error("the cursor is not in a function");
    return;
  }
  collected_t col;
  if ( !collect_function_context(func_ea, &col) )
  {
    log_error("%s", col.error.c_str());
    return;
  }
  msg("Claude-Rays Decompiler: collected context of %s (%u chars, about %u tokens):\n",
      hex_str(func_ea).c_str(), unsigned(col.text.size()), unsigned(col.text.size() / 4));
  for ( const auto &line : split_lines(col.text) )
    msg("%s\n", line.c_str());
  for ( const auto &sz : col.sizes )
    msg("Claude-Rays Decompiler: section %-36s %6u chars\n", sz.first.c_str(), unsigned(sz.second));
}

//------------------------------------------------------------------------------
// the answers are collected in the main thread by wait_requests()
//------------------------------------------------------------------------------
void clauderays_t::poll_requests()
{
  // the Cancel button of the wait box
  if ( user_cancelled() && waitbox != nullptr )
  {
    request_t *r = find_request(waitbox->func_ea, waitbox->mode());
    if ( r != nullptr && !r->cancelled )
    {
      r->cancelled = true;
      cancel_job(r->job.get());
      log_info("cancelling the decompilation of %s", r->func_name.c_str());
    }
  }
  for ( size_t i = 0; i < requests.size(); )
  {
    request_t &r = *requests[i];
    if ( !r.job->done )
    {
      i++;
      continue;
    }
    if ( r.job->thread.joinable() )
      r.job->thread.join();
    // a cancelled request does not start another round
    if ( !r.cancelled && r.fixing )
      finish_fix(r);
    else if ( !r.cancelled )
      finish_round(r);
    else
      view_show_status(r.func_ea, r.mode(), { strfmt("Claude-Rays Decompiler: the decompilation of %s was cancelled.", r.func_name.c_str()),
                                    "Claude-Rays Decompiler/Regenerate tries again." });
    // a new round restarts the job; otherwise the request is over
    if ( r.job->done )
    {
      hide_progress(&r);
      requests.erase(requests.begin() + i);
    }
    else
    {
      i++;
    }
  }
}

void clauderays_t::finish_round(request_t &req)
{
  job_t &job = *req.job;
  std::string err;
  json_t inner;
  decomp_result_t res;
  usage_t u;
  if ( !job.ok )
    err = job.error;
  else if ( extract_result(job, &inner, &err, &u) && !decode_result(inner, &res, &err) )
    err = safety_error(u, &inner, "error unpacking the answer (" + err + ")");
  req.usage.add(u);
  if ( !err.empty() )
  {
    log_error("decompiling %s with '%s' failed: %s", req.func_name.c_str(), req.model.c_str(), err.c_str());
    std::vector<std::string> status;
    status.push_back(strfmt("Claude-Rays Decompiler: decompiling %s with %s failed:", req.func_name.c_str(), req.model_text().c_str()));
    for ( const auto &l : split_lines(err) )
      status.push_back(l);
    status.push_back("Claude-Rays Decompiler/Regenerate tries again.");
    view_show_status(req.func_ea, req.mode(), status);
    return;
  }
  if ( get_func(req.func_ea) == nullptr )
  {
    log_error("%s is no longer a function: the answer is dropped", hex_str(req.func_ea).c_str());
    return;
  }
  log_debug("%s round %d: %u uncertain, %u context request(s)", req.func_name.c_str(), req.round,
            unsigned(res.uncertain.size()), unsigned(res.need_more.size()));
  for ( const auto &n : res.need_more )
    log_debug("  need_more %s %s: %s", n.what.c_str(), n.target.c_str(), n.reason.c_str());

  std::vector<std::string> missing;
  if ( !res.need_more.empty() )
  {
    if ( req.round < MAX_ROUNDS )
    {
      size_t before = req.ignored.size();
      std::string extra = collect_requested(res.need_more, &req.seen,
                                            size_t(settings().budget) / 2, &req.ignored);
      if ( !extra.empty() )
      {
        req.round++;
        req.requested += extra;
        log_info("%s: the model asked for more context (round %d/%d)",
                 req.func_name.c_str(), req.round, MAX_ROUNDS);
        start_round(req);
        return;
      }
      missing.assign(req.ignored.begin() + before, req.ignored.end());
    }
    else
    {
      for ( const auto &n : res.need_more )
        missing.push_back(n.what + " " + n.target + ": " + n.reason + " (no rounds left)");
    }
  }
  finalize(req, res, missing);
}

void clauderays_t::finalize(request_t &req, const decomp_result_t &res, const std::vector<std::string> &missing)
{
  cache_entry_t e;
  e.bytes_hash = func_bytes_hash(req.func_ea);
  e.names_hash = func_names_hash(req.func_ea);
  e.model = req.model;
  e.effort = req.effort;
  e.model_id = req.usage.model_id;
  e.date = now_str();
  e.cost_usd = req.usage.cost_usd;
  e.input_tokens = req.usage.input_tokens;
  e.output_tokens = req.usage.output_tokens;
  e.safety_stops = req.usage.safety_stops;
  e.models = req.usage.models;
  e.summary = res.summary;
  e.prototype = res.prototype;
  e.code = res.code;
  e.uncertain = res.uncertain;
  e.warnings = validate_result(req.func_ea, res);
  e.analyzed = req.analyze;
  if ( req.analyze )
    e.findings = anchor_findings(req.func_ea, res.findings, &e.warnings);
  e.missing = missing;
  e.rounds = req.round;
  // the colors of the result this one replaces go (those of the other
  // commands of the function stay), its own come
  cache_entry_t old;
  if ( cache_load(req.func_ea, req.mode(), &old) != CS_NONE && !old.findings.empty() )
  {
    color_findings(old.findings, false);
    for ( cache_mode_t m : CACHE_MODES )
    {
      cache_entry_t other;
      if ( m != req.mode() && cache_load(req.func_ea, m, &other) != CS_NONE )
        color_findings(other.findings, true);
    }
  }
  cache_save(req.func_ea, req.mode(), e);
  color_findings(e.findings, true);
  uint64 ms = get_nsec_stamp() / 1000000 - req.started_ms;
  log_info("%s decompiled by %s in %.1f s (%d extra round(s), %u warning(s), %u uncertain, "
           "%" FMT_64 "d in / %" FMT_64 "d out tokens, $%.4f at API prices)%s",
           req.func_name.c_str(), model_used_str(e).c_str(), double(ms) / 1000.0, req.round,
           unsigned(e.warnings.size()), unsigned(e.uncertain.size()),
           e.input_tokens, e.output_tokens, e.cost_usd,
           req.analyze ? strfmt(", %u security finding(s)", unsigned(e.findings.size())).c_str() : "");
  for ( const auto &f : e.findings )
    log_info("  %s", finding_text(f).c_str());
  for ( const auto &w : e.warnings )
    log_info("  warning: %s", w.c_str());
  if ( e.safety_stops > 0 )
    log_info("  %s", safety_note(e.safety_stops, e.models).c_str());
  if ( req.patch )
  {
    req.entry = e;
    req.entry_state = CS_VALID;
    if ( !wanted_fixes(e.findings).empty() )
    {
      start_fix(req);
      return;
    }
    log_info("%s: no confirmed or possible finding, nothing to fix", req.func_name.c_str());
  }
  view_show_result(req.func_ea, req.mode(), e, CS_VALID);
}

//------------------------------------------------------------------------------
// Decompile, analyze and patch: the fixes of the findings of req.entry (the
// confirmed and possible ones), in a second query
//------------------------------------------------------------------------------
void clauderays_t::start_fix(request_t &req)
{
  const settings_t &s = settings();
  req.fixing = true;
  req.asked = wanted_fixes(req.entry.findings);
  std::vector<std::string> texts;
  for ( const auto &f : req.entry.findings )
    texts.push_back(finding_text(f));
  req.job.reset(new job_t);
  job_t *job = req.job.get();
  job->model = req.model;
  job->effort = req.effort;
  job->claude_path = s.claude_path;
  job->timeout = s.timeout;
  job->system_prompt = fix_system_prompt();
  job->schema = fix_schema();
  job->prompt = fix_prompt(req.entry.summary, req.entry.prototype, req.entry.code, texts, req.asked);
  log_debug_text("fix input:", job->prompt);
  std::string mt = req.effort.empty() ? req.model : req.model + ", effort " + req.effort;
  view_show_status(req.func_ea, req.mode(), {
    strfmt("Claude-Rays Decompiler: writing the fixes of %u finding(s) of %s with %s...",
           unsigned(req.asked.size()), req.func_name.c_str(), mt.c_str()),
    "Cancel in the wait box stops it; the decompilation and its analysis are already cached." });
  std::string text = strfmt("Claude is fixing %s (%s)...\n", req.func_name.c_str(), mt.c_str());
  text += "This can take a while (it depends on the size of the function, the connection\n"
          "and Claude's own processing).";
  if ( waitbox == &req )
  {
    replace_wait_box("%s", text.c_str());
  }
  else if ( waitbox == nullptr )
  {
    show_wait_box("NODELAY\n%s", text.c_str());
    waitbox = &req;
  }
  req.started_ms = get_nsec_stamp() / 1000000;
  job->thread = std::thread(run_job, job);
}

// A failed query leaves the result without fixes: it is shown as it is.
void clauderays_t::finish_fix(request_t &req)
{
  job_t &job = *req.job;
  cache_entry_t &e = req.entry;
  std::string err;
  json_t inner;
  usage_t u;
  if ( !job.ok )
    err = job.error;
  else if ( extract_result(job, &inner, &err, &u) )
  {
    // a safety stop can leave the answer without any fix
    const json_t *given = inner.get("fixes");
    if ( given == nullptr || !given->is_arr() || given->arr.empty() )
      err = safety_error(u, &inner, std::string());
  }
  if ( !err.empty() || get_func(req.func_ea) == nullptr )
  {
    if ( err.empty() )
      err = "the function is gone";
    log_error("the fixes of %s failed: %s (the result is shown without them; Decompile, analyze and patch "
              "tries again)", req.func_name.c_str(), err.c_str());
    e.warnings.push_back("the fixes could not be made: " + one_line(err, 300));
    view_show_result(req.func_ea, req.mode(), e, req.entry_state);
    return;
  }
  fix_result_t r;
  r.model = req.model;
  r.effort = req.effort;
  r.model_id = u.model_id;
  r.date = now_str();
  r.cost_usd = u.cost_usd;
  r.input_tokens = u.input_tokens;
  r.output_tokens = u.output_tokens;
  r.safety_stops = u.safety_stops;
  r.models = u.models;
  r.fixes = decode_fixes(inner, split_lines(e.code), req.asked, &r.warnings);
  e.fix = r;
  e.has_fix = true;
  cache_save(req.func_ea, req.mode(), e);
  size_t nfixed = 0;
  for ( const auto &f : r.fixes )
    nfixed += f.edits.empty() ? 0 : 1;
  uint64 ms = get_nsec_stamp() / 1000000 - req.started_ms;
  log_info("%s: %u of %u finding(s) fixed by %s in %.1f s (%u edit(s), %u warning(s), "
           "%lld in / %lld out tokens, $%.4f at API prices)",
           req.func_name.c_str(), unsigned(nfixed), unsigned(req.asked.size()), fix_model_used(r).c_str(),
           double(ms) / 1000.0, unsigned(r.edits().size()), unsigned(r.warnings.size()),
           r.input_tokens, r.output_tokens, r.cost_usd);
  for ( const auto &w : r.warnings )
    log_info("  fix warning: %s", w.c_str());
  if ( r.safety_stops > 0 )
    log_info("  %s", safety_note(r.safety_stops, r.models).c_str());
  view_show_result(req.func_ea, req.mode(), e, req.entry_state);
}

// the fixes of the function as a unified diff, in its patch view
void clauderays_t::generate_patch(ea_t func_ea) const
{
  cache_entry_t e;
  if ( func_ea == BADADDR || cache_load(func_ea, CM_PATCH, &e) == CS_NONE || !e.has_fix || !e.fix.has_edits() )
  {
    log_info("there is no fix to make a patch of (Claude-Rays Decompiler/Decompile, analyze and patch)");
    return;
  }
  qstring qname;
  get_func_name(&qname, func_ea);
  std::string name = qname.empty() ? hex_str(func_ea) : qname.c_str();
  view_show_patch(func_ea, name, fix_patch_lines(name, func_ea, e));
}

//------------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( !is_idaq() )
    return nullptr;   // the plugin is all about UI
  settings().load();
  for ( const char *line : LOGO_LINES )
    msg("%s\n", line);
  msg("Claude-Rays Decompiler for IDA Free/Pro %s by ClaudeMonkey (Claude-Rays/claude-rays-decompiler-idafree)\n",
      CLAUDERAYS_VERSION);
  const settings_t &s = settings();
  log_info("version %s loaded, default model: %s, models: %s, claude: %s, shortcut: %s",
           CLAUDERAYS_VERSION, s.default_model.c_str(), s.models_str().c_str(),
           s.claude_path.c_str(), s.hotkey.c_str());
  log_info("disclaimer: treat the output of this plugin as a hypothesis, not as the truth, "
           "especially on hostile binaries");
  return new clauderays_t;
}

} // namespace clauderays

//------------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  clauderays::init,
  nullptr,
  nullptr,
  "Claude-Rays Decompiler for IDA Free/Pro " CLAUDERAYS_VERSION " - decompile a function with Claude from its disassembly",
  "Right-click in the disassembly view and pick Claude-Rays Decompiler/Decompile (Ctrl+Shift+F5 by default). "
  "Edit > Plugins > Claude-Rays Decompiler opens the settings.",
  "Claude-Rays Decompiler",
  "",
};
