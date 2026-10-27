// Claude-Rays Decompiler - the code view
#include "view.hpp"
#include "validate.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <parsejson.hpp>
#include <segment.hpp>
#include <xref.hpp>

#include <functional>
#include <map>
#include <set>

namespace clauderays
{

// a background behind the characters [cpx, cpx + nchars) of a line
struct view_seg_t
{
  int cpx;
  int nchars;
  bgcolor_t bg;                   // 0xAABBGGRR, with alpha
};

struct view_t
{
  ea_t func_ea = BADADDR;
  cache_mode_t mode = CM_DECOMPILE;   // each command has its own view of the function
  strvec_t lines;
  // address of each line (the first /*0x...*/ annotation the model wrote on
  // it, BADADDR if none): the annotations are usually not shown
  std::vector<ea_t> line_eas;
  std::string code;               // plain code as shown, for Copy code
  bool patched = false;           // the result has fixes with edits: shown side by side
  std::map<int, std::string> tips;  // the findings of each line, for its hint
  // backgrounds behind some characters of a line (side by side, each column
  // has its own), drawn through ui_get_lines_rendering_info
  std::map<int, std::vector<view_seg_t>> segs;
  TWidget *widget = nullptr;
  // what the function refers to, by every name the code may use for it
  // (mangled, demangled, without templates, last component; no spaces);
  // BADADDR marks a name shared by several addresses
  std::map<std::string, ea_t> names;
};

// open views by widget
static std::map<TWidget *, view_t *> g_views;

// the open patches (Generate patch) by widget, with the patch as text
struct patch_view_t
{
  ea_t func_ea = BADADDR;
  strvec_t lines;
  std::string text;
};
static std::map<TWidget *, patch_view_t *> g_patch_views;

// called on a double click on another function
static void (*g_open_function)(ea_t) = nullptr;

//------------------------------------------------------------------------------
// highlighter
//------------------------------------------------------------------------------
static std::string col(color_t c, const std::string &s)
{
  if ( s.empty() )
    return s;
  std::string out;
  out += COLOR_ON;
  out += char(c);
  out += s;
  out += COLOR_OFF;
  out += char(c);
  return out;
}

static bool is_ident_char(char c)
{
  return isalnum((unsigned char)c) || c == '_' || c == '$';
}

static const std::set<std::string> &keywords()
{
  static const std::set<std::string> kw =
  {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "return", "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "union", "unsigned", "void", "volatile", "while", "bool", "true", "false",
    "NULL", "nullptr", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_BOOL1", "_BOOL4",
    "__int8", "__int16", "__int32", "__int64", "__int128",
    "__fastcall", "__cdecl", "__stdcall", "__thiscall", "__usercall", "__noreturn",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t",
  };
  return kw;
}

struct highlighter_t
{
  bool in_comment = false;                 // inside a multi line /* */
  std::map<std::string, color_t> names;    // database name lookups

  color_t name_color(const std::string &tok)
  {
    auto p = names.find(tok);
    if ( p != names.end() )
      return p->second;
    color_t c = COLOR_DEFAULT;
    ea_t ea = get_name_ea(BADADDR, tok.c_str());
    if ( ea != BADADDR && is_mapped(ea) )
    {
      segment_t *seg = getseg(ea);
      if ( seg != nullptr && (seg->type == SEG_XTRN || seg->type == SEG_IMP) )
        c = COLOR_IMPNAME;
      else
        c = is_code(get_flags(ea)) ? COLOR_CNAME : COLOR_DNAME;
    }
    names[tok] = c;
    return c;
  }

  std::string line(const std::string &s)
  {
    std::string out;
    size_t i = 0;
    size_t n = s.size();
    while ( i < n )
    {
      if ( in_comment )
      {
        size_t e = s.find("*/", i);
        size_t end = e == std::string::npos ? n : e + 2;
        out += col(COLOR_REGCMT, s.substr(i, end - i));
        in_comment = e == std::string::npos;
        i = end;
        continue;
      }
      char c = s[i];
      if ( c == '/' && i + 1 < n && s[i + 1] == '/' )
      {
        out += col(COLOR_REGCMT, s.substr(i));
        break;
      }
      if ( c == '/' && i + 1 < n && s[i + 1] == '*' )
      {
        size_t e = s.find("*/", i + 2);
        size_t end = e == std::string::npos ? n : e + 2;
        std::string body = s.substr(i, end - i);
        // the address annotations are dimmed
        bool annotation = body.compare(0, 4, "/*0x") == 0 && e != std::string::npos;
        out += col(annotation ? COLOR_AUTOCMT : COLOR_REGCMT, body);
        in_comment = e == std::string::npos;
        i = end;
        continue;
      }
      if ( c == '"' || c == '\'' )
      {
        size_t j = i + 1;
        while ( j < n && s[j] != c )
          j += s[j] == '\\' ? 2 : 1;
        j = qmin(j + 1, n);
        out += col(c == '"' ? COLOR_DSTR : COLOR_DCHAR, s.substr(i, j - i));
        i = j;
        continue;
      }
      if ( isdigit((unsigned char)c) )
      {
        size_t j = i;
        while ( j < n && (isalnum((unsigned char)s[j]) || s[j] == '.') )
          j++;
        out += col(COLOR_DNUM, s.substr(i, j - i));
        i = j;
        continue;
      }
      if ( is_ident_char(c) )
      {
        size_t j = i;
        while ( j < n && is_ident_char(s[j]) )
          j++;
        std::string tok = s.substr(i, j - i);
        if ( keywords().count(tok) != 0 )
          out += col(COLOR_KEYWORD, tok);
        else
          out += col(name_color(tok), tok);
        i = j;
        continue;
      }
      out += c;
      i++;
    }
    return out;
  }
};

// tabs expanded, color escape characters removed
static std::string clean_line(const std::string &s)
{
  std::string out;
  for ( char c : s )
  {
    if ( c == '\t' )
      out.append(4 - out.size() % 4, ' ');
    else if ( requires_color_esc(c) || c == '\r' )
      continue;
    else
      out += c;
  }
  return out;
}

//------------------------------------------------------------------------------
// code shaping: the /*0x...*/ annotations are taken out of the lines (their
// address is kept per line) and the code is indented again, because the model
// often writes the annotation in place of the indentation
//------------------------------------------------------------------------------
static const int INDENT = 4;

// 'line' without its annotations; *ea receives the first one (or BADADDR)
static std::string strip_annotations(const std::string &line, ea_t *ea)
{
  *ea = BADADDR;
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
        if ( *ea == BADADDR )
          *ea = ea_t(strtoull(line.substr(i + 4, e - i - 4).c_str(), nullptr, 16));
        i = e + 2;
        if ( i < line.size() && line[i] == ' ' )
          i++;
        continue;
      }
    }
    out += line[i++];
  }
  // annotations at the end of a line leave trailing blanks
  while ( !out.empty() && (out.back() == ' ' || out.back() == '\t') )
    out.pop_back();
  return out;
}

static bool starts_with_word(const std::string &t, const char *w)
{
  size_t n = strlen(w);
  return t.compare(0, n, w) == 0 && (t.size() == n || !is_ident_char(t[n]));
}

// brace / parenthesis balance of a line, outside strings, chars and comments
struct line_scan_t
{
  int braces = 0;
  int parens = 0;
  char last = 0;                  // last significant character
  bool opens_comment = false;     // ends inside a /* comment
  bool leading_close = false;     // the first significant character is '}'
};

static line_scan_t scan_line(const std::string &t)
{
  line_scan_t r;
  bool first = true;
  for ( size_t i = 0; i < t.size(); i++ )
  {
    char c = t[i];
    if ( c == '/' && i + 1 < t.size() && t[i + 1] == '/' )
      break;
    if ( c == '/' && i + 1 < t.size() && t[i + 1] == '*' )
    {
      size_t e = t.find("*/", i + 2);
      if ( e == std::string::npos )
      {
        r.opens_comment = true;
        break;
      }
      i = e + 1;
      continue;
    }
    if ( c == '"' || c == '\'' )
    {
      size_t j = i + 1;
      while ( j < t.size() && t[j] != c )
        j += t[j] == '\\' ? 2 : 1;
      i = j;
      r.last = c;
      first = false;
      continue;
    }
    if ( c == ' ' || c == '\t' )
      continue;
    if ( first && c == '}' )
      r.leading_close = true;
    first = false;
    if ( c == '{' )
      r.braces++;
    else if ( c == '}' )
      r.braces--;
    else if ( c == '(' )
      r.parens++;
    else if ( c == ')' )
      r.parens--;
    r.last = c;
  }
  return r;
}

// Shape the code for the view: annotations out (or kept), indentation rebuilt
// from the braces, single-statement bodies of if/else/for/while, case labels
// and the continuation lines of an open parenthesis.
void shape_code(const std::string &code, bool keep_annotations,
                std::vector<std::string> *out, std::vector<ea_t> *eas)
{
  int depth = 0;
  int parens = 0;
  int pending = 0;                // single-statement bodies waiting
  bool in_comment = false;
  std::vector<int> case_depths;   // brace depths of the active case labels
  for ( const auto &raw : split_lines(code) )
  {
    ea_t ea = BADADDR;
    std::string stripped = strip_annotations(raw, &ea);
    eas->push_back(ea);
    if ( keep_annotations )
    {
      out->push_back(raw);
      continue;
    }
    std::string t = trim(stripped);
    if ( in_comment )
    {
      // a block comment keeps its own layout
      out->push_back(stripped);
      in_comment = stripped.find("*/") == std::string::npos;
      continue;
    }
    if ( t.empty() )
    {
      out->push_back(std::string());
      continue;
    }
    line_scan_t s = scan_line(t);
    bool is_case = starts_with_word(t, "case") || starts_with_word(t, "default");
    int base = s.leading_close ? qmax(depth - 1, 0) : depth;
    while ( !case_depths.empty() && case_depths.back() > base )
      case_depths.pop_back();
    int lvl = base;
    for ( int d : case_depths )
      if ( is_case ? d < base : d <= base )
        lvl++;
    if ( t[0] == '#' )
      lvl = 0;
    else if ( parens > 0 )
      lvl += pending + 1;           // continuation of an open parenthesis
    else if ( t[0] == '{' )
      lvl += qmax(pending - 1, 0);  // the brace of the last header
    else if ( !s.leading_close )
      lvl += pending;
    out->push_back(std::string(size_t(lvl * INDENT), ' ') + t);

    if ( is_case && (case_depths.empty() || case_depths.back() != depth) )
      case_depths.push_back(depth);
    depth = qmax(depth + s.braces, 0);
    parens = qmax(parens + s.parens, 0);
    in_comment = s.opens_comment;
    bool comment_only = t.compare(0, 2, "//") == 0 || (t.compare(0, 2, "/*") == 0 && s.last == 0);
    if ( comment_only || parens > 0 )
      continue;
    bool header = starts_with_word(t, "if") || starts_with_word(t, "else") || starts_with_word(t, "for")
               || starts_with_word(t, "while") || starts_with_word(t, "do")
               || (s.leading_close && t.find("else") != std::string::npos);
    if ( s.last == '{' || s.last == ';' || s.last == '}' || s.last == ':' )
      pending = 0;
    else if ( header )
      pending++;
  }
}

//------------------------------------------------------------------------------
// navigation
//------------------------------------------------------------------------------
static void jump_to_disasm(ea_t ea)
{
  // jumpto() acts on the last active disassembly view
  TWidget *w = find_widget("IDA View-A");
  if ( w != nullptr )
    activate_widget(w, true);
  jumpto(ea);
}

static ea_t annotation_in(const std::string &line, size_t from = 0)
{
  std::vector<ea_t> notes = code_annotations(line.substr(qmin(from, line.size())));
  return notes.empty() ? BADADDR : notes[0];
}

static std::string no_spaces(const std::string &s)
{
  std::string out;
  for ( char c : s )
    if ( c != ' ' && c != '\t' )
      out += c;
  return out;
}

static void add_name(view_t *v, const std::string &name, ea_t ea)
{
  std::string key = no_spaces(name);
  if ( key.empty() )
    return;
  auto p = v->names.find(key);
  if ( p == v->names.end() )
    v->names[key] = ea;
  else if ( p->second != ea )
    p->second = BADADDR;
}

// the functions and data the function refers to, by all their names
static void collect_names(view_t *v)
{
  v->names.clear();
  func_t *pfn = get_func(v->func_ea);
  if ( pfn == nullptr )
    return;
  std::set<ea_t> targets;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
  {
    xrefblk_t xb;
    for ( bool x = xb.first_from(fii.current(), XREF_NOFLOW); x; x = xb.next_from() )
      if ( !func_contains(pfn, xb.to) )
        targets.insert(xb.to);
  }
  for ( ea_t t : targets )
  {
    for ( const auto &n : callee_name_variants(t) )
      add_name(v, n, t);
    for ( const auto &n : demangled_names(t) )
      add_name(v, strip_templates(n), t);
  }
}

static bool is_operator_char(char c)
{
  return strchr("+-*/%=<>!&|^~[]", c) != nullptr && c != '\0';
}

// the qualified name under column 'x': "Ns::Cls<T>::f", "std::operator+",
// "Cls::~Cls"; "" if none
static std::string qualified_token(const std::string &line, size_t x)
{
  auto ident = [](char c) { return is_ident_char(c) || c == '~'; };
  if ( x >= line.size() || !ident(line[x]) )
    return std::string();
  size_t b = x;
  for ( ;; )
  {
    if ( b > 0 && ident(line[b - 1]) )
      b--;
    else if ( b >= 2 && line[b - 1] == ':' && line[b - 2] == ':' )
      b -= 2;
    else if ( b > 0 && line[b - 1] == '>' )
    {
      int depth = 0;
      size_t i = b;
      while ( i > 0 )
      {
        char c = line[--i];
        if ( c == '>' )
          depth++;
        else if ( c == '<' && --depth == 0 )
          break;
      }
      if ( depth != 0 )
        break;
      b = i;
    }
    else
    {
      break;
    }
  }
  size_t e = x;
  for ( ;; )
  {
    if ( e < line.size() && ident(line[e]) )
      e++;
    else if ( e + 1 < line.size() && line[e] == ':' && line[e + 1] == ':' )
      e += 2;
    else if ( e < line.size() && line[e] == '<' )
    {
      int depth = 0;
      size_t i = e;
      for ( ; i < line.size(); i++ )
      {
        if ( line[i] == '<' )
          depth++;
        else if ( line[i] == '>' && --depth == 0 )
          break;
        else if ( line[i] == ';' || line[i] == '(' || line[i] == ')' )
          break;
      }
      if ( i >= line.size() || line[i] != '>' )
        break;
      e = i + 1;
    }
    else
    {
      break;
    }
  }
  std::string tok = line.substr(b, e - b);
  // operator+, operator==...
  if ( tok.size() >= 8 && tok.compare(tok.size() - 8, 8, "operator") == 0 )
    while ( e < line.size() && is_operator_char(line[e]) )
      tok += line[e++];
  return tok;
}

// the address of the name or number under column 'x' (*is_name tells which
// one), or of the annotation under it
static ea_t target_at(const view_t &v, const std::string &line, int x, bool *is_name)
{
  *is_name = false;
  if ( x < 0 || size_t(x) >= line.size() )
    return BADADDR;
  // inside an annotation
  for ( size_t p = line.find("/*0x"); p != std::string::npos; p = line.find("/*0x", p + 1) )
  {
    size_t e = line.find("*/", p + 4);
    if ( e != std::string::npos && size_t(x) >= p && size_t(x) < e + 2 )
      return annotation_in(line, p);
  }
  // a name the function refers to, possibly qualified
  std::string q = no_spaces(qualified_token(line, size_t(x)));
  for ( const std::string &key : { q, strip_templates(q) } )
  {
    auto p = v.names.find(key);
    if ( !key.empty() && p != v.names.end() && p->second != BADADDR )
    {
      *is_name = true;
      return p->second;
    }
  }
  // any other name or a number under the cursor
  size_t b = size_t(x);
  if ( !is_ident_char(line[b]) )
    return BADADDR;
  while ( b > 0 && is_ident_char(line[b - 1]) )
    b--;
  size_t e = size_t(x);
  while ( e < line.size() && is_ident_char(line[e]) )
    e++;
  std::string tok = line.substr(b, e - b);
  if ( keywords().count(tok) != 0 )
    return BADADDR;
  if ( isdigit((unsigned char)tok[0]) && tok.compare(0, 2, "0x") != 0 )
    return BADADDR;
  ea_t ea = parse_address(tok);
  *is_name = ea != BADADDR && !isdigit((unsigned char)tok[0]);
  return ea;
}

// a function worth decompiling: not a library function, a thunk or an import
static bool decompilable(ea_t ea)
{
  func_t *f = get_func(ea);
  return f != nullptr && f->start_ea == ea && (f->flags & (FUNC_LIB | FUNC_THUNK)) == 0;
}

static bool idaapi view_dblclick(TWidget *cv, int shift, void *ud)
{
  view_t *v = static_cast<view_t *>(ud);
  int x = 0;
  int y = 0;
  place_t *pl = get_custom_viewer_place(cv, false, &x, &y);
  if ( pl == nullptr )
    return false;
  int n = int(static_cast<simpleline_place_t *>(pl)->n);
  if ( n < 0 || size_t(n) >= v->lines.size() )
    return false;
  std::string line = tag_removed(v->lines[n].line);
  bool is_name = false;
  ea_t target = target_at(*v, line, x, &is_name);
  // another function: its Claude-Rays Decompiler view, like Hex-Rays does (Shift+double
  // click goes to the disassembly instead)
  if ( is_name && target != v->func_ea && (shift & VES_SHIFT) == 0
    && g_open_function != nullptr && decompilable(target) )
  {
    g_open_function(target);
    return true;
  }
  // the address of the line, or of the closest line above
  for ( int i = n; target == BADADDR && i >= 0; i-- )
    target = size_t(i) < v->line_eas.size() ? v->line_eas[i] : BADADDR;
  if ( target == BADADDR )
    return false;
  jump_to_disasm(target);
  return true;
}

static void idaapi view_close(TWidget *w, void *ud)
{
  g_views.erase(w);
  delete static_cast<view_t *>(ud);
}

static const custom_viewer_handlers_t view_handlers(
        nullptr,          // keyboard
        nullptr,          // popup
        nullptr,          // mouse_moved
        nullptr,          // click
        view_dblclick,
        nullptr,          // curpos
        view_close);

//------------------------------------------------------------------------------
static view_t *find_view(ea_t func_ea, cache_mode_t mode)
{
  for ( auto &kv : g_views )
    if ( kv.second->func_ea == func_ea && kv.second->mode == mode )
      return kv.second;
  return nullptr;
}

// "Claude-Rays Decompiler: main (Decompile and analyze)"
static std::string view_title(ea_t func_ea, cache_mode_t mode)
{
  qstring name;
  get_func_name(&name, func_ea);
  return "Claude-Rays Decompiler: " + std::string(name.empty() ? hex_str(func_ea).c_str() : name.c_str())
       + " (" + cache_mode_label(mode) + ")";
}

// Show 'lines' (already colored) in the view of 'func_ea' and 'mode', creating it if
// needed. 'display' false leaves a new widget undisplayed: IDA places it
// itself when it restores a desktop.
// what a result adds to its lines: the security findings
struct line_marks_t
{
  bool patched = false;
  std::map<int, int> ranks;           // line -> rank of its most severe finding
  std::map<int, bgcolor_t> backs;     // line -> its background (other than a finding's)
  std::map<int, std::string> tips;    // line -> its findings
  std::map<int, std::vector<view_seg_t>> segs;
};

static TWidget *show_lines(ea_t func_ea, cache_mode_t mode, const std::vector<std::string> &lines,
                           const std::string &code, const std::vector<ea_t> &eas = std::vector<ea_t>(),
                           bool display = true, const line_marks_t &marks = line_marks_t())
{
  view_t *v = find_view(func_ea, mode);
  bool created = v == nullptr;
  if ( created )
  {
    v = new view_t;
    v->func_ea = func_ea;
    v->mode = mode;
  }
  v->lines.clear();
  for ( const auto &l : lines )
    v->lines.push_back(simpleline_t(l.c_str()));
  if ( v->lines.empty() )
    v->lines.push_back(simpleline_t(""));
  for ( const auto &r : marks.ranks )
    if ( r.first >= 0 && size_t(r.first) < v->lines.size() )
      v->lines[r.first].bgcolor = finding_color(r.second);
  for ( const auto &r : marks.backs )
    if ( r.first >= 0 && size_t(r.first) < v->lines.size() )
      v->lines[r.first].bgcolor = r.second;
  v->patched = marks.patched;
  v->tips = marks.tips;
  v->segs = marks.segs;
  v->line_eas = eas;
  v->line_eas.resize(v->lines.size(), BADADDR);
  v->code = code;
  collect_names(v);

  simpleline_place_t s1(0);
  simpleline_place_t s2(int(v->lines.size() - 1));
  if ( created )
  {
    std::string title = view_title(func_ea, mode);
    // a view left from an earlier session of the plugin
    TWidget *old = find_widget(title.c_str());
    if ( old != nullptr )
      close_widget(old, 0);
    v->widget = create_custom_viewer(title.c_str(), &s1, &s2, &s1, nullptr,
                                     &v->lines, &view_handlers, v);
    if ( v->widget == nullptr )
    {
      delete v;
      log_error("cannot create the view '%s'", title.c_str());
      return nullptr;
    }
    g_views[v->widget] = v;
    if ( display )
      display_widget(v->widget, WOPN_DP_TAB | WOPN_RESTORE);
  }
  else
  {
    set_custom_viewer_range(v->widget, &s1, &s2);
    jumpto(v->widget, &s1, 0, 0);
    refresh_custom_viewer(v->widget);
    if ( display )
      activate_widget(v->widget, true);
  }
  return v->widget;
}

static std::vector<std::string> status_lines(const std::vector<std::string> &status)
{
  std::vector<std::string> lines;
  for ( const auto &s : status )
    lines.push_back(col(COLOR_AUTOCMT, "// " + clean_line(s)));
  return lines;
}

void view_show_status(ea_t func_ea, cache_mode_t mode, const std::vector<std::string> &status)
{
  show_lines(func_ea, mode, status_lines(status), std::string());
}

// the colored lines of a result (header notes, summary, code) and its code
bgcolor_t finding_color(int rank)
{
  // 0xBBGGRR
  switch ( rank )
  {
    case 0:  return 0xCCCCFF;
    case 1:  return 0xB0DDFF;
    default: return 0xB8F6FF;
  }
}

std::string finding_text(const finding_t &f)
{
  std::string pre = trim(f.precondition);
  std::string low = pre;
  for ( auto &c : low )
    c = char(tolower((unsigned char)c));
  bool no_pre = pre.empty() || low.compare(0, 4, "none") == 0;
  std::string level = f.level;
  for ( auto &c : level )
    c = char(toupper((unsigned char)c));
  std::string addrs;
  for ( const auto &a : f.addresses )
    addrs += (addrs.empty() ? "" : ", ") + a;
  return level + " " + (f.cls.empty() ? std::string("finding") : f.cls) + " at " + addrs + ": " + f.description
       + (no_pre ? std::string() : " Precondition: " + pre);
}

// The background of the lines of a fix (Decompile, analyze and patch): pale
// green, darker the more severe its finding.
bgcolor_t fix_color(int rank)
{
  // 0xBBGGRR
  switch ( rank )
  {
    case 0:  return 0xA8E4A8;
    case 1:  return 0xC8F0C8;
    default: return 0xE4F8E4;
  }
}

// "F1 CONFIRMED stack buffer overflow at 0x401020: ..."
static std::string numbered_finding(int n, const finding_t &f)
{
  return "F" + std::to_string(n) + " " + finding_text(f);
}

// the findings of the code lines, by line: the most severe rank, the finding
// numbers and their texts
struct finding_lines_t
{
  std::map<int, int> ranks;
  std::map<int, std::set<int>> numbers;
  std::map<int, std::string> tips;
};

// The code lines of each finding: the statement that holds each of its
// instructions is the line annotated with that address, or else with the
// closest address below it (a statement starts at its first instruction).
static finding_lines_t find_finding_lines(const std::vector<finding_t> &findings, const std::vector<ea_t> &eas)
{
  finding_lines_t out;
  std::map<ea_t, std::vector<int>> by_ea;
  for ( size_t i = 0; i < eas.size(); i++ )
    if ( eas[i] != BADADDR )
      by_ea[eas[i]].push_back(int(i));
  for ( size_t n = 1; n <= findings.size(); n++ )
  {
    const finding_t &f = findings[n - 1];
    std::string text = numbered_finding(int(n), f);
    for ( const auto &s : f.addresses )
    {
      ea_t ea = ea_t(strtoull(s.c_str(), nullptr, 16));
      auto p = by_ea.upper_bound(ea);
      if ( p == by_ea.begin() )
        continue;
      --p;
      for ( int line : p->second )
      {
        auto r = out.ranks.find(line);
        if ( r == out.ranks.end() || f.rank() < r->second )
          out.ranks[line] = f.rank();
        out.numbers[line].insert(int(n));
        std::string &tip = out.tips[line];
        if ( tip.find(text) == std::string::npos )
          tip += (tip.empty() ? "" : "\n") + text;
      }
    }
  }
  return out;
}

// the same, as the marks of the lines of a view whose code starts at line 0
static void mark_findings(const std::vector<finding_t> &findings, const std::vector<ea_t> &eas, line_marks_t *marks)
{
  finding_lines_t fl = find_finding_lines(findings, eas);
  marks->ranks.insert(fl.ranks.begin(), fl.ranks.end());
  marks->tips.insert(fl.tips.begin(), fl.tips.end());
}

// What became of the fix of each finding ('note' adds header lines, 'back'
// the background of the lines it added last).
static void fix_notes(const cache_entry_t &e, const std::function<void(color_t, const std::string &)> &note,
                      const std::function<void(bgcolor_t)> &back)
{
  if ( e.fix.safety_stops > 0 )
    note(COLOR_MACRO, "SAFETY STOP (fixes): " + safety_note(e.fix.safety_stops, e.fix.models));
  for ( const auto &w : e.fix.warnings )
    note(COLOR_ERROR, "WARNING: " + w);
  for ( size_t n = 1; n <= e.findings.size(); n++ )
  {
    const finding_t &f = e.findings[n - 1];
    const fix_t *fx = e.fix.fix_of(int(n));
    std::string fn = "F" + std::to_string(n);
    if ( fx == nullptr )
    {
      note(COLOR_AUTOCMT, fn + " not fixed: " + f.level + " finding.");
    }
    else if ( !fx->edits.empty() )
    {
      note(COLOR_AUTOCMT, fn + " FIXED: " + fx->note);
      back(fix_color(f.rank()));
    }
    else if ( fx->fixable )
    {
      note(COLOR_AUTOCMT, fn + " no edits (covered by another fix, or nothing to change): " + fx->note);
    }
    else
    {
      note(COLOR_MACRO, fn + " NOT FIXABLE in this function: " + fx->note);
    }
  }
}

static void patched_lines(const cache_entry_t &e, cache_state_t state,
                          std::vector<std::string> *out, std::vector<ea_t> *out_eas, std::string *out_code,
                          line_marks_t *marks);

// the summary as a block comment ("/*\n * ...\n */\n"), "" if empty
static std::string summary_comment(const std::string &summary)
{
  if ( trim(summary).empty() )
    return std::string();
  std::string code = "/*\n";
  for ( const auto &l : split_lines(summary) )
  {
    std::string t = l;
    // a "*/" inside would end the block early
    for ( size_t p = t.find("*/"); p != std::string::npos; p = t.find("*/", p) )
      t.replace(p, 2, "* /");
    code += t.empty() ? " *\n" : " * " + t + "\n";
  }
  return code + " */\n";
}

std::string fix_model_used(const fix_result_t &r)
{
  std::string s = r.model;
  if ( !r.model_id.empty() && r.model_id != r.model )
    s += " -> " + r.model_id;
  if ( !r.effort.empty() )
    s += ", effort " + r.effort;
  return s;
}

// shape_code() of some lines, with one shaped line for each of them (an empty last line too)
static void shape_lines(const std::vector<std::string> &lines, bool keep_annotations,
                        std::vector<std::string> *out, std::vector<ea_t> *eas)
{
  std::string code;
  for ( size_t i = 0; i < lines.size(); i++ )
    code += (i == 0 ? "" : "\n") + lines[i];
  size_t before = out->size();
  shape_code(code, keep_annotations, out, eas);
  while ( out->size() - before < lines.size() )
  {
    out->push_back(std::string());
    eas->push_back(BADADDR);
  }
}

// characters shown (UTF-8 code points, no color tags)
static size_t visible_len(const std::string &s)
{
  size_t n = 0;
  for ( unsigned char c : s )
    if ( (c & 0xC0) != 0x80 )
      n++;
  return n;
}

static void result_lines(const cache_entry_t &e, cache_state_t state,
                         std::vector<std::string> *out, std::vector<ea_t> *out_eas, std::string *out_code,
                         line_marks_t *marks)
{
  if ( e.has_fix && e.fix.has_edits() )
  {
    patched_lines(e, state, out, out_eas, out_code, marks);
    return;
  }
  std::vector<std::string> &lines = *out;
  auto note = [&](color_t c, const std::string &text)
  {
    for ( const auto &l : split_lines(text) )
      lines.push_back(col(c, "// " + clean_line(l)));
  };
  note(COLOR_AUTOCMT, strfmt("Claude-Rays Decompiler: C reconstructed by Claude (%s, %s) from the disassembly. "
                             "Plausible, not proven: check it against the listing.",
                             model_used_str(e).c_str(), e.date.c_str()));
  if ( e.derived_from >= 0 )
    note(COLOR_AUTOCMT, strfmt("Taken from the cached result of %s: nothing was queried "
                               "(Claude-Rays Decompiler/Regenerate makes one of its own).",
                               cache_mode_label(cache_mode_t(e.derived_from))));
  if ( e.input_tokens > 0 || e.output_tokens > 0 )
    note(COLOR_AUTOCMT, strfmt("Usage: %" FMT_64 "d input / %" FMT_64 "d output tokens, "
                               "$%.4f at API prices (on a subscription it counts against the plan usage).",
                               e.input_tokens, e.output_tokens, e.cost_usd));
  if ( e.rounds > 0 )
    note(COLOR_AUTOCMT, strfmt("Context asked by the model: %d extra round(s).", e.rounds));
  if ( e.safety_stops > 0 )
    note(COLOR_MACRO, "SAFETY STOP: " + safety_note(e.safety_stops, e.models));
  if ( state == CS_STALE )
    note(COLOR_ERROR, "STALE: the names of the called functions changed since this was generated "
                      "(Claude-Rays Decompiler/Regenerate).");
  for ( const auto &w : e.warnings )
    note(COLOR_ERROR, "WARNING: " + w);
  for ( const auto &u : e.uncertain )
    note(COLOR_MACRO, "UNCERTAIN " + u.address + ": " + u.reason);
  for ( const auto &m : e.missing )
    note(COLOR_ERROR, "CONTEXT NOT GIVEN: " + m);
  if ( e.analyzed )
  {
    note(COLOR_AUTOCMT, strfmt("SECURITY ANALYSIS of this function alone: %u finding(s). Red: confirmed in the "
                               "code; orange: possible, needs the precondition; yellow: theoretical.",
                               unsigned(e.findings.size())));
    for ( size_t n = 1; n <= e.findings.size(); n++ )
    {
      size_t first = lines.size();
      note(COLOR_AUTOCMT, numbered_finding(int(n), e.findings[n - 1]));
      for ( size_t i = first; i < lines.size(); i++ )
        marks->ranks[int(i)] = e.findings[n - 1].rank();
    }
  }
  if ( e.has_fix )
  {
    note(COLOR_AUTOCMT, strfmt("FIXES (%s, %s): none of the findings could be fixed in this function.",
                               fix_model_used(e.fix).c_str(), e.fix.date.c_str()));
    size_t first = lines.size();
    fix_notes(e, [&](color_t c, const std::string &t) { first = lines.size(); note(c, t); },
              [&](bgcolor_t bg) { for ( size_t i = first; i < lines.size(); i++ ) marks->backs[int(i)] = bg; });
  }
  lines.push_back(std::string());

  // the header comment written by the model, before the code
  std::string code = summary_comment(e.summary) + e.code;

  // the header notes have no address
  out_eas->assign(lines.size(), BADADDR);
  std::vector<std::string> shaped;
  shape_code(code, settings().show_annotations, &shaped, out_eas);
  highlighter_t hl;
  std::string shown;
  for ( const auto &l : shaped )
  {
    lines.push_back(hl.line(clean_line(l)));
    shown += l + "\n";
  }
  *out_code = shown;
  if ( e.analyzed )
    mark_findings(e.findings, *out_eas, marks);
}

// The side by side view: the notes of the result and of its fixes over the
// whole width, then the decompiled code on the left as the analysis shows it
// and the fixed code on the right, aligned row by row (blank rows fill the
// side with fewer lines). The changed rows have the number of their finding
// in the margin of both columns and, on the right, the green of the severity
// of the finding; the lines of the findings keep their color on the left.
static void patched_lines(const cache_entry_t &e, cache_state_t state,
                          std::vector<std::string> *out, std::vector<ea_t> *out_eas, std::string *out_code,
                          line_marks_t *marks)
{
  std::vector<std::string> &lines = *out;
  auto note = [&](color_t c, const std::string &text)
  {
    for ( const auto &l : split_lines(text) )
      for ( const auto &w : wrap_text(l, 140) )
        lines.push_back(col(c, "// " + clean_line(w)));
  };
  // the notes of the result, as without the fixes (and without its code)
  {
    cache_entry_t plain = e;
    plain.has_fix = false;
    std::vector<std::string> head;
    std::vector<ea_t> head_eas;
    std::string head_code;
    line_marks_t head_marks;
    result_lines(plain, state, &head, &head_eas, &head_code, &head_marks);
    // up to the blank line before the code
    size_t n = 0;
    while ( n < head.size() && !head[n].empty() )
      n++;
    lines.assign(head.begin(), head.begin() + n);
    for ( const auto &r : head_marks.ranks )
      if ( size_t(r.first) < n )
        marks->ranks[r.first] = r.second;
  }
  marks->patched = true;
  note(COLOR_AUTOCMT, strfmt("FIXES suggested by Claude (%s, %s) for the findings: a patch of the decompiled C, "
                             "not of the binary. Plausible, not proven.",
                             fix_model_used(e.fix).c_str(), e.fix.date.c_str()));
  if ( e.fix.input_tokens > 0 || e.fix.output_tokens > 0 )
    note(COLOR_AUTOCMT, strfmt("Usage of the fixes: %lld input / %lld output tokens, $%.4f at API prices.",
                               e.fix.input_tokens, e.fix.output_tokens, e.fix.cost_usd));
  note(COLOR_AUTOCMT, "Left: the decompiled code; right: the fixed code. Green: the lines of each fix, darker the "
                      "more severe its finding; F<n> in the margin pairs them with their finding. "
                      "Claude-Rays Decompiler/Generate patch makes a unified diff.");
  size_t first = lines.size();
  fix_notes(e, [&](color_t c, const std::string &t) { first = lines.size(); note(c, t); },
            [&](bgcolor_t bg) { for ( size_t i = first; i < lines.size(); i++ ) marks->backs[int(i)] = bg; });
  lines.push_back(std::string());
  out_eas->assign(lines.size(), BADADDR);

  // both sides: the summary, then the code (fixed on the right)
  std::vector<std::string> summary = split_lines(summary_comment(e.summary));
  int nsummary = int(summary.size());
  std::vector<std::string> code_lines = split_lines(e.code);
  std::vector<fix_edit_t> edits = e.fix.edits();
  std::vector<std::string> fixed = apply_fixes(code_lines, edits);
  std::vector<std::string> left_src = summary;
  left_src.insert(left_src.end(), code_lines.begin(), code_lines.end());
  std::vector<std::string> right_src = summary;
  right_src.insert(right_src.end(), fixed.begin(), fixed.end());
  bool keep = settings().show_annotations;
  std::vector<std::string> sl, sr;
  std::vector<ea_t> sl_eas, sr_eas;
  shape_lines(left_src, keep, &sl, &sl_eas);
  shape_lines(right_src, keep, &sr, &sr_eas);
  for ( auto &l : sl )
    l = clean_line(l);
  for ( auto &l : sr )
    l = clean_line(l);
  std::vector<fix_row_t> rows;
  for ( int i = 0; i < nsummary; i++ )
    rows.push_back({ i, i, 0 });
  for ( const auto &r : fix_rows(int(code_lines.size()), edits) )
    rows.push_back({ r.left >= 0 ? nsummary + r.left : -1, r.right >= 0 ? nsummary + r.right : -1, r.finding });

  // the findings of the left lines and the margin of every row
  finding_lines_t fl = find_finding_lines(e.findings, sl_eas);
  std::vector<std::string> labels;
  size_t margin = 4;
  size_t width = 20;
  for ( const auto &r : rows )
  {
    std::set<int> nums;
    if ( r.left >= 0 && fl.numbers.count(r.left) != 0 )
      nums = fl.numbers[r.left];
    if ( r.changed() )
      nums.insert(r.finding);
    std::string label;
    for ( int n : nums )
      label += (label.empty() ? "F" : ",") + std::to_string(n);
    labels.push_back(label);
    margin = qmax(margin, label.size() + 1);
    if ( r.left >= 0 )
      width = qmax(width, visible_len(sl[r.left]));
  }
  auto fix_note = [&](int n) -> std::string
  {
    const fix_t *fx = e.fix.fix_of(n);
    return fx != nullptr ? fx->note : std::string();
  };
  // "<margin><left><pad> | <margin><right>"
  const int right_col = int(margin + width + 3 + margin);
  highlighter_t hl, hr;
  std::string shown;
  for ( size_t k = 0; k < rows.size(); k++ )
  {
    const fix_row_t &r = rows[k];
    int row = int(lines.size());
    std::string left_text = r.left >= 0 ? sl[r.left] : std::string();
    std::string right_text = r.right >= 0 ? sr[r.right] : std::string();
    std::string lmark = labels[k] + std::string(margin - labels[k].size(), ' ');
    std::string rlabel = r.changed() ? "F" + std::to_string(r.finding) : std::string();
    std::string rmark = rlabel + std::string(margin - qmin(margin, rlabel.size()), ' ');
    std::string pad(width - qmin(width, visible_len(left_text)), ' ');
    lines.push_back(col(COLOR_SYMBOL, lmark) + hl.line(left_text) + pad + " " + col(COLOR_SYMBOL, "|") + " "
                  + col(COLOR_SYMBOL, rmark) + hr.line(right_text));
    ea_t ea = r.left >= 0 ? sl_eas[r.left] : BADADDR;
    if ( ea == BADADDR && r.right >= 0 )
      ea = sr_eas[r.right];
    out_eas->push_back(ea);
    if ( r.left >= 0 )
      shown += sl[r.left] + "\n";
    std::vector<std::string> tips;
    if ( r.left >= 0 && fl.ranks.count(r.left) != 0 )
    {
      marks->segs[row].push_back({ 0, int(margin + width), 0xB0000000 | finding_color(fl.ranks[r.left]) });
      tips.push_back(fl.tips[r.left]);
    }
    if ( r.changed() )
    {
      const finding_t &f = e.findings[r.finding - 1];
      if ( r.right >= 0 )
        marks->segs[row].push_back({ right_col - int(margin), int(margin + qmax(visible_len(right_text), size_t(1))),
                                     0xB0000000 | fix_color(f.rank()) });
      std::string t = numbered_finding(r.finding, f);
      bool listed = false;
      for ( const auto &x : tips )
        listed |= x.find(t) != std::string::npos;
      if ( !listed )
        tips.push_back(t);
      tips.push_back("FIX: " + fix_note(r.finding));
    }
    std::string tip;
    for ( const auto &t : tips )
      tip += (tip.empty() ? "" : "\n") + t;
    if ( !tip.empty() )
      marks->tips[row] = tip;
  }
  *out_code = shown;
}

std::vector<std::string> fix_patch_lines(const std::string &func_name, ea_t func_ea, const cache_entry_t &e)
{
  std::vector<std::string> out;
  for ( const auto &l : wrap_text(strfmt("Claude-Rays Decompiler: suggested fix of %s at %s (%s, %s). A patch of "
                                         "the C decompiled by Claude, not of the binary: plausible, not proven.",
                                         func_name.c_str(), hex_str(func_ea).c_str(),
                                         fix_model_used(e.fix).c_str(), e.fix.date.c_str()), 100) )
    out.push_back(l);
  for ( size_t n = 1; n <= e.findings.size(); n++ )
  {
    const fix_t *fx = e.fix.fix_of(int(n));
    std::string what = fx == nullptr ? "not fixed (" + e.findings[n - 1].level + ")"
                     : !fx->edits.empty() ? "FIXED: " + fx->note
                     : fx->fixable ? "no edits (covered by another fix, or nothing to change): " + fx->note
                     : "NOT FIXABLE in this function: " + fx->note;
    for ( const auto &l : wrap_text("F" + std::to_string(n) + " " + finding_text(e.findings[n - 1]), 100) )
      out.push_back(l);
    for ( const auto &l : wrap_text(what, 96) )
      out.push_back("    " + l);
  }
  out.push_back(std::string());
  std::vector<std::string> code = split_lines(e.code);
  std::vector<fix_edit_t> edits = e.fix.edits();
  std::vector<std::string> left, right;
  std::vector<ea_t> left_eas, right_eas;
  shape_lines(code, false, &left, &left_eas);
  shape_lines(apply_fixes(code, edits), false, &right, &right_eas);
  for ( const auto &l : fix_unified_diff(left, right, fix_rows(int(code.size()), edits), 3,
                                         "a/" + func_name + " (decompiled)", "b/" + func_name + " (fixed)") )
    out.push_back(l);
  return out;
}

static void idaapi patch_view_close(TWidget *w, void *ud)
{
  g_patch_views.erase(w);
  delete static_cast<patch_view_t *>(ud);
}

static const custom_viewer_handlers_t patch_view_handlers(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, patch_view_close);

void view_show_patch(ea_t func_ea, const std::string &func_name, const std::vector<std::string> &lines)
{
  std::string title = "Claude-Rays Decompiler patch: " + func_name;
  TWidget *old = find_widget(title.c_str());
  if ( old != nullptr )
    close_widget(old, 0);
  patch_view_t *pv = new patch_view_t;
  pv->func_ea = func_ea;
  bool in_diff = false;
  for ( const auto &l : lines )
  {
    pv->text += l + "\n";
    in_diff |= l.compare(0, 4, "--- ") == 0;
    std::string t = clean_line(l);
    simpleline_t sl;
    if ( !in_diff )
      sl.line = col(COLOR_AUTOCMT, t).c_str();
    else if ( t.compare(0, 4, "--- ") == 0 || t.compare(0, 4, "+++ ") == 0 )
      sl.line = col(COLOR_KEYWORD, t).c_str();
    else if ( t.compare(0, 2, "@@") == 0 )
      sl.line = col(COLOR_DNUM, t).c_str();
    else
      sl.line = t.c_str();
    if ( in_diff && !t.empty() && t[0] == '+' && t.compare(0, 4, "+++ ") != 0 )
      sl.bgcolor = fix_color(1);
    else if ( in_diff && !t.empty() && t[0] == '-' && t.compare(0, 4, "--- ") != 0 )
      sl.bgcolor = finding_color(0);
    pv->lines.push_back(sl);
  }
  if ( pv->lines.empty() )
    pv->lines.push_back(simpleline_t(""));
  simpleline_place_t s1(0);
  simpleline_place_t s2(int(pv->lines.size() - 1));
  TWidget *w = create_custom_viewer(title.c_str(), &s1, &s2, &s1, nullptr, &pv->lines, &patch_view_handlers, pv);
  if ( w == nullptr )
  {
    delete pv;
    log_error("cannot create the view '%s'", title.c_str());
    return;
  }
  g_patch_views[w] = pv;
  display_widget(w, WOPN_DP_TAB | WOPN_RESTORE);
}

bool view_is_patch(TWidget *w)
{
  return g_patch_views.find(w) != g_patch_views.end();
}

void view_rendering_info(lines_rendering_output_t *out, const TWidget *widget, const lines_rendering_input_t *info)
{
  auto p = g_views.find(const_cast<TWidget *>(widget));
  if ( p == g_views.end() || out == nullptr || info == nullptr || p->second->segs.empty() )
    return;
  const view_t *v = p->second;
  for ( const auto &section : info->sections_lines )
  {
    for ( const twinline_t *line : section )
    {
      if ( line == nullptr || line->at == nullptr )
        continue;
      int n = int(static_cast<const simpleline_place_t *>(line->at)->n);
      auto s = v->segs.find(n);
      if ( s == v->segs.end() )
        continue;
      for ( const auto &seg : s->second )
        if ( seg.nchars > 0 )
          out->entries.push_back(new line_rendering_output_entry_t(line, seg.cpx, seg.nchars, 0, seg.bg));
    }
  }
}

void view_show_result(ea_t func_ea, cache_mode_t mode, const cache_entry_t &e, cache_state_t state)
{
  std::vector<std::string> lines;
  std::vector<ea_t> eas;
  std::string code;
  line_marks_t marks;
  result_lines(e, state, &lines, &eas, &code, &marks);
  show_lines(func_ea, mode, lines, code, eas, true, marks);
}

//------------------------------------------------------------------------------
// desktop: IDA saves the open views with the database and asks for them again
// when it reopens it
//------------------------------------------------------------------------------
static const char CFG_FUNC[] = "clauderays_func";
static const char CFG_MODE[] = "clauderays_mode";

void view_get_config(const TWidget *w, jobj_t *cfg)
{
  auto p = g_views.find(const_cast<TWidget *>(w));
  if ( p != g_views.end() && cfg != nullptr )
  {
    cfg->put(CFG_FUNC, int64(p->second->func_ea));
    cfg->put(CFG_MODE, cache_mode_key(p->second->mode));
  }
}

// the most complete command with a cached result for 'func_ea' (Decompile if none)
static cache_mode_t saved_mode(ea_t func_ea)
{
  for ( cache_mode_t m : { CM_PATCH, CM_ANALYZE } )
  {
    cache_entry_t e;
    if ( cache_load(func_ea, m, &e) != CS_NONE )
      return m;
  }
  return CM_DECOMPILE;
}

TWidget *view_create_for_desktop(const char *title, const jobj_t *cfg)
{
  if ( title == nullptr || cfg == nullptr || strncmp(title, "Claude-Rays Decompiler: ", 24) != 0 )
    return nullptr;
  int64 v = 0;
  if ( !cfg->get(&v, CFG_FUNC) )
    return nullptr;
  ea_t func_ea = ea_t(v);
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr || pfn->start_ea != func_ea )
    return nullptr;
  // saved by a version with one view per function: the command of its result
  qstring key;
  cache_mode_t mode = saved_mode(func_ea);
  if ( cfg->get(&key, CFG_MODE) )
    for ( cache_mode_t m : CACHE_MODES )
      if ( key == cache_mode_key(m) )
        mode = m;
  std::vector<std::string> lines;
  std::vector<ea_t> eas;
  std::string code;
  line_marks_t marks;
  cache_entry_t e;
  cache_state_t st = cache_load_or_derive(func_ea, mode, &e);
  if ( st != CS_NONE )
    result_lines(e, st, &lines, &eas, &code, &marks);
  else
    lines = status_lines({ "Claude-Rays Decompiler: no cached result for this function (never finished, or its bytes changed).",
                           "Claude-Rays Decompiler/Regenerate decompiles it." });
  return show_lines(func_ea, mode, lines, code, eas, false, marks);
}

ea_t view_function(TWidget *w)
{
  auto p = g_views.find(w);
  return p == g_views.end() ? BADADDR : p->second->func_ea;
}

std::string view_code(TWidget *w)
{
  auto pp = g_patch_views.find(w);
  if ( pp != g_patch_views.end() )
    return pp->second->text;
  auto p = g_views.find(w);
  return p == g_views.end() ? std::string() : p->second->code;
}

cache_mode_t view_mode(TWidget *w)
{
  auto p = g_views.find(w);
  return p == g_views.end() ? CM_DECOMPILE : p->second->mode;
}

bool view_patched(TWidget *w)
{
  auto p = g_views.find(w);
  return p != g_views.end() && p->second->patched;
}

bool view_hint(TWidget *w, const place_t *place, qstring *hint, int *important_lines)
{
  auto p = g_views.find(w);
  if ( p == g_views.end() || place == nullptr )
    return false;
  int n = int(static_cast<const simpleline_place_t *>(place)->n);
  auto t = p->second->tips.find(n);
  if ( t == p->second->tips.end() )
    return false;
  for ( const auto &l : split_lines(t->second) )
  {
    hint->append(l.c_str());
    hint->append("\n");
    (*important_lines)++;
  }
  return true;
}

void view_close_all()
{
  std::vector<TWidget *> ws;
  for ( auto &kv : g_views )
    ws.push_back(kv.first);
  for ( auto &kv : g_patch_views )
    ws.push_back(kv.first);
  for ( TWidget *w : ws )
    close_widget(w, 0);
  // the close callback deletes the views; drop what is left anyway
  for ( auto &kv : g_views )
    delete kv.second;
  g_views.clear();
  for ( auto &kv : g_patch_views )
    delete kv.second;
  g_patch_views.clear();
}

void view_refresh_all()
{
  std::vector<std::pair<ea_t, cache_mode_t>> funcs;
  for ( const auto &kv : g_views )
    if ( !kv.second->code.empty() )
      funcs.push_back({ kv.second->func_ea, kv.second->mode });
  for ( const auto &f : funcs )
  {
    ea_t ea = f.first;
    cache_entry_t e;
    cache_state_t st = cache_load_or_derive(ea, f.second, &e);
    if ( st == CS_NONE )
      continue;
    std::vector<std::string> lines;
    std::vector<ea_t> eas;
    std::string code;
    line_marks_t marks;
    result_lines(e, st, &lines, &eas, &code, &marks);
    show_lines(ea, f.second, lines, code, eas, false, marks);
  }
}

void view_set_open_function(void (*cb)(ea_t func_ea))
{
  g_open_function = cb;
}

} // namespace clauderays
