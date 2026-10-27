// Claude-Rays Decompiler - the code view
// A read-only custom viewer per function and command ("Claude-Rays Decompiler:
// <function> (<command>)") with the C code colored by a simple highlighter. Double click on another function
// opens its view (decompiling it if needed; Shift+double click: disassembly),
// on any other name jumps to it,
// on any other place of a line to the address of its annotation.
#pragma once

#include "common.hpp"
#include "cache.hpp"

struct jobj_t;     // parsejson.hpp

namespace clauderays
{

// open (or update) the view of 'func_ea' and 'mode' with a status message,
// e.g. while the query runs
void view_show_status(ea_t func_ea, cache_mode_t mode, const std::vector<std::string> &status);

// open (or update) the view of 'func_ea' and 'mode' with a result
void view_show_result(ea_t func_ea, cache_mode_t mode, const cache_entry_t &e, cache_state_t state);

// the function shown by 'w', BADADDR if 'w' is not a Claude-Rays Decompiler view
ea_t view_function(TWidget *w);

// the code shown by 'w' without the header ("" if none); of a patch view, the patch
std::string view_code(TWidget *w);

// the command of the view 'w' (CM_DECOMPILE if 'w' is not a Claude-Rays Decompiler view)
cache_mode_t view_mode(TWidget *w);

// ui_get_custom_viewer_hint: the findings of the line under the mouse;
// false if 'w' is not ours or the line has none
bool view_hint(TWidget *w, const place_t *place, qstring *hint, int *important_lines);

// The background of a security finding of rank 'rank' (finding_t::rank():
// soft red confirmed, soft orange possible, yellow theoretical), for the view
// and for the disassembly
bgcolor_t finding_color(int rank);

// "CONFIRMED stack buffer overflow at 0x401020: ... Precondition: ..."
std::string finding_text(const finding_t &f);

// the result shown by 'w' has fixes with edits: it is shown side by side
bool view_patched(TWidget *w);

// The background of the lines of a fix of a finding of rank 'rank': pale
// green, darker the more severe
bgcolor_t fix_color(int rank);

// "opus -> claude-opus-5-5, effort medium"
std::string fix_model_used(const fix_result_t &r);

// Generate patch: a header with each finding and what became of its fix, then
// the unified diff of the code as the view shows it (indented, without the
// address comments)
std::vector<std::string> fix_patch_lines(const std::string &func_name, ea_t func_ea, const cache_entry_t &e);

// open (or replace) the patch view of 'func_ea' ("Claude-Rays Decompiler patch: <function>")
void view_show_patch(ea_t func_ea, const std::string &func_name, const std::vector<std::string> &lines);

// 'w' is a patch view (view_code() gives its patch)
bool view_is_patch(TWidget *w);

// ui_get_lines_rendering_info: the backgrounds of the columns of a side by side view
void view_rendering_info(lines_rendering_output_t *out, const TWidget *widget, const lines_rendering_input_t *info);

// close every view (the callbacks live in this DLL)
void view_close_all();

// show the cached result of every open view again (after a display setting
// changed); views with a status message are left alone
void view_refresh_all();

// desktop persistence (ui_get_widget_config / ui_create_desktop_widget): the
// function and the command of a view go into its saved config, and a saved view is created
// again (from the cache, not displayed: IDA places it); nullptr if 'title' is
// not ours
void view_get_config(const TWidget *w, jobj_t *cfg);
TWidget *view_create_for_desktop(const char *title, const jobj_t *cfg);

// The code as the view shows it: the /*0x...*/ annotations taken out (or
// kept) and the indentation rebuilt from the braces; *eas receives the
// address of each line (its first annotation, BADADDR if none)
void shape_code(const std::string &code, bool keep_annotations,
                std::vector<std::string> *out, std::vector<ea_t> *eas);

// what a double click on another (decompilable) function does; nullptr
// jumps to the disassembly as for any other name
void view_set_open_function(void (*cb)(ea_t func_ea));

} // namespace clauderays
