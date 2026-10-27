// Claude-Rays Decompiler - cheap validation of an answer
#include "validate.hpp"
#include "collector.hpp"
#include "insn_facts.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <name.hpp>
#include <ua.hpp>

#include <algorithm>
#include <set>

namespace clauderays
{

static const size_t MAX_LISTED = 8;     // warnings of one kind listed one by one

//------------------------------------------------------------------------------
std::vector<ea_t> code_annotations(const std::string &code)
{
  std::vector<ea_t> out;
  for ( size_t p = code.find("/*0x"); p != std::string::npos; p = code.find("/*0x", p + 4) )
  {
    size_t q = p + 4;
    size_t e = q;
    while ( e < code.size() && isxdigit((unsigned char)code[e]) )
      e++;
    if ( e == q || e - q > 16 || code.compare(e, 2, "*/") != 0 )
      continue;
    out.push_back(ea_t(strtoull(code.substr(q, e - q).c_str(), nullptr, 16)));
  }
  return out;
}

//------------------------------------------------------------------------------
static bool has_identifier(const std::string &code, const std::string &name)
{
  if ( name.empty() )
    return false;
  for ( size_t p = code.find(name); p != std::string::npos; p = code.find(name, p + 1) )
  {
    bool left = p == 0 || !(isalnum((unsigned char)code[p - 1]) || code[p - 1] == '_');
    size_t e = p + name.size();
    bool right = e >= code.size() || !(isalnum((unsigned char)code[e]) || code[e] == '_');
    if ( left && right )
      return true;
  }
  return false;
}

std::vector<std::string> callee_name_variants(ea_t callee)
{
  std::vector<std::string> out;
  auto add = [&](std::string n)
  {
    n = trim(n);
    if ( !n.empty() && std::find(out.begin(), out.end(), n) == out.end() )
      out.push_back(n);
  };
  std::string name = ea_name(callee);
  add(name);
  // names IDA made unique: _CxxThrowException_0
  size_t us = name.rfind('_');
  if ( us != std::string::npos && us > 0 && us + 1 < name.size()
    && name.find_first_not_of("0123456789", us + 1) == std::string::npos )
  {
    name = name.substr(0, us);
    add(name);
  }
  // import pointers: __imp_CreateFileW, __imp__CreateFileW@28 (the second
  // one may be _CreateFileW or CreateFileW: both are tried below)
  std::string n = name;
  for ( const char *prefix : { "__imp_", "_imp_" } )
    if ( n.compare(0, strlen(prefix), prefix) == 0 )
    {
      n = n.substr(strlen(prefix));
      break;
    }
  add(n);
  size_t at = n.find('@');
  if ( at != std::string::npos && at > 0 )
    n = n.substr(0, at);
  add(n);
  if ( n.size() > 1 && n[0] == '_' )
    add(n.substr(1));
  // j_foo thunks
  if ( n.compare(0, 2, "j_") == 0 )
    add(n.substr(2));
  // demangled C++ names: qualified and last component, with and without
  // template arguments (the model spaces them its own way)
  for ( const auto &q : demangled_names(callee) )
  {
    add(q);
    size_t colons = last_scope(q);
    if ( colons != std::string::npos )
      add(q.substr(colons + 2));
  }
  return out;
}

// the "::" before the last component, outside template arguments
size_t last_scope(const std::string &s)
{
  int depth = 0;
  bool quoted = false;
  size_t found = std::string::npos;
  for ( size_t i = 0; i + 1 < s.size(); i++ )
  {
    if ( s[i] == '`' )
      quoted = true;
    else if ( s[i] == '\'' )
      quoted = false;
    else if ( quoted )
      continue;
    else if ( s[i] == '<' )
      depth++;
    else if ( s[i] == '>' && depth > 0 )
      depth--;
    else if ( depth == 0 && s[i] == ':' && s[i + 1] == ':' )
      found = i++;
  }
  return found;
}

std::string strip_templates(const std::string &s)
{
  std::string out;
  int depth = 0;
  for ( char c : s )
  {
    if ( c == '<' )
      depth++;
    else if ( c == '>' && depth > 0 )
      depth--;
    else if ( depth == 0 )
      out += c;
  }
  return out;
}

std::vector<std::string> demangled_names(ea_t ea)
{
  std::vector<std::string> out;
  qstring sn;
  if ( get_short_name(&sn, ea) <= 0 )
    return out;
  std::string s = sn.c_str();
  // the arguments: the first '(' outside template arguments and outside
  // quoted scopes like `Flag<T>::Get(void)'::`2'
  int depth = 0;
  bool quoted = false;
  size_t paren = std::string::npos;
  for ( size_t i = 0; i < s.size(); i++ )
  {
    if ( s[i] == '`' )
      quoted = true;
    else if ( s[i] == '\'' )
      quoted = false;
    else if ( quoted )
      continue;
    else if ( s[i] == '<' )
      depth++;
    else if ( s[i] == '>' && depth > 0 )
      depth--;
    else if ( s[i] == '(' && depth == 0 )
    {
      paren = i;
      break;
    }
  }
  if ( paren != std::string::npos )
    s = s.substr(0, paren);
  s = trim(s);
  if ( s.empty() || s == ea_name(ea) )
    return out;
  out.push_back(s);
  std::string bare = strip_templates(s);
  if ( bare != s && !bare.empty() )
    out.push_back(bare);
  return out;
}

// compiler helpers that a decompiler may leave out of the code: stack
// cookies, stack probes, CFG checks
static bool is_compiler_helper(ea_t callee)
{
  static const char *const helpers[] =
  {
    "security_check_cookie", "stack_chk_fail", "RTC_CheckStackVars", "chkstk",
    "alloca_probe", "guard_check_icall", "guard_dispatch_icall", "GSHandlerCheck",
  };
  std::string name = ea_name(callee);
  for ( const char *h : helpers )
    if ( name.find(h) != std::string::npos )
      return true;
  return false;
}

// Calls that idiomatic C++ does not spell out: destructors (implicit at the end
// of a scope or of a full expression)
static bool is_destructor(ea_t callee)
{
  for ( const auto &q : demangled_names(callee) )
  {
    size_t colons = last_scope(q);
    std::string last = colons == std::string::npos ? q : q.substr(colons + 2);
    if ( !last.empty() && last[0] == '~' )
      return true;
  }
  return false;
}

// ... and the runtime call behind a C++ 'throw'
static bool is_throw_helper(ea_t callee)
{
  std::string name = ea_name(callee);
  return name.find("CxxThrowException") != std::string::npos
      || name.find("cxa_throw") != std::string::npos;
}

// Epilogue restore of a callee-saved register from its home slot on the
// stack: 'mov rbx, [rsp+80h+arg_8]'
static bool restores_saved_reg(ea_t ea)
{
  static const char *const saved[] =
  {
    "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15", "ebx", "ebp", "esi", "edi",
  };
  qstring op0;
  qstring op1;
  print_operand(&op0, ea, 0);
  print_operand(&op1, ea, 1);
  std::string dst = tag_removed(op0);
  std::string src = tag_removed(op1);
  bool saved_dst = false;
  for ( const char *r : saved )
    saved_dst |= dst == r;
  bool stack_src = src.find("[rsp") != std::string::npos || src.find("[esp") != std::string::npos
                || src.find("[r11") != std::string::npos;   // MSVC: lea r11, [rsp+...] first
  return saved_dst && stack_src;
}

// A block that needs no statement: only unconditional jumps / nops, or a
// function epilogue (stack cookie check, stack release, pops, return)
static bool trivial_block(ea_t start, ea_t end)
{
  bool helper_call = false;
  bool cookie_ops = false;      // mov / xor / lea that prepare the cookie check
  for ( ea_t ea = start; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    if ( !is_code(get_flags(ea)) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
    std::string m = insn_mnem(ea);
    if ( m.compare(0, 3, "nop") == 0 || m == "int3" || m == "endbr64" || m == "endbr32" )
      continue;
    if ( is_call_insn(insn) )
    {
      ea_t t = call_target(ea);
      if ( t == BADADDR || !is_compiler_helper(t) )
        return false;
      helper_call = true;
      continue;
    }
    if ( is_ret_insn(insn) || m == "pop" || m == "leave" )
      continue;
    if ( m == "add" )
    {
      // only the release of the stack frame
      qstring op;
      print_operand(&op, ea, 0);
      std::string reg = tag_removed(op);
      if ( reg != "rsp" && reg != "esp" )
        return false;
      continue;
    }
    if ( m == "mov" && restores_saved_reg(ea) )
      continue;
    if ( m == "mov" || m == "xor" || m == "lea" )
    {
      cookie_ops = true;
      continue;
    }
    bool jump = (insn.get_canon_feature(PH) & CF_STOP) != 0 && insn.ops[0].type == o_near;
    if ( !jump )
      return false;
  }
  // a "mov eax, 1; ret" block is a real return statement
  return !cookie_ops || helper_call;
}

static const int MERGED_MAX_INSNS = 4;

// A piece of an expression rather than a statement: a few instructions that
// only compare, branch or set a register ('flag = a == 2 || a == 5' leaves
// blocks like 'mov r9b, 1' or 'xor r9b, r9b; jmp'). No call, no store.
static bool merged_block(ea_t start, ea_t end)
{
  int n = 0;
  for ( ea_t ea = start; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    if ( !is_code(get_flags(ea)) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 || is_call_insn(insn) || ++n > MERGED_MAX_INSNS )
      return false;
    std::string m = insn_mnem(ea);
    if ( m == "cmp" || m == "test" || m[0] == 'j' )
      continue;
    bool reg_dest = insn.ops[0].type == o_reg;
    if ( reg_dest && (m == "mov" || m == "xor" || m == "or" || m == "and"
                   || m == "movzx" || m.compare(0, 3, "set") == 0) )
    {
      continue;
    }
    return false;
  }
  return n > 0;
}

static int block_of(const qflow_chart_t &fc, ea_t ea)
{
  for ( int i = 0; i < fc.nproper; i++ )
    if ( fc.blocks[i].start_ea <= ea && ea < fc.blocks[i].end_ea )
      return i;
  return -1;
}

// Every call to 'callee' follows an annotation of its own block with no other
// call in between: the statement written there is that call, under whatever
// name the model gave it.
static bool call_sites_annotated(func_t *pfn, ea_t callee, const std::set<ea_t> &notes, const qflow_chart_t &fc)
{
  int sites = 0;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
  {
    ea_t ea = fii.current();
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 || !is_call_insn(insn) || call_target(ea) != callee )
      continue;
    sites++;
    auto p = notes.upper_bound(ea);
    if ( p == notes.begin() )
      return false;
    ea_t note = *--p;
    int blk = block_of(fc, ea);
    if ( blk < 0 || block_of(fc, note) != blk )
      return false;
    for ( ea_t x = note; x < ea; x = next_head(x, ea) )
    {
      insn_t other;
      if ( is_code(get_flags(x)) && decode_insn(&other, x) > 0 && is_call_insn(other) )
        return false;
    }
  }
  return sites > 0;
}

static void add_list(std::vector<std::string> *out, const std::string &what, const std::vector<std::string> &items)
{
  if ( items.empty() )
    return;
  std::string s = what;
  for ( size_t i = 0; i < items.size() && i < MAX_LISTED; i++ )
    s += (i == 0 ? " " : ", ") + items[i];
  if ( items.size() > MAX_LISTED )
    s += strfmt(" and %u more", unsigned(items.size() - MAX_LISTED));
  out->push_back(s);
}

//------------------------------------------------------------------------------
std::vector<finding_t> anchor_findings(ea_t func_ea, const std::vector<finding_t> &findings,
                                       std::vector<std::string> *warnings)
{
  std::vector<finding_t> out;
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr )
    return out;
  for ( const auto &x : findings )
  {
    std::vector<std::string> kept;
    std::vector<std::string> bad;
    for ( const auto &s : x.addresses )
    {
      ea_t ea = parse_address(s);
      ea_t head = ea != BADADDR ? get_item_head(ea) : BADADDR;
      if ( head == BADADDR || !is_code(get_flags(head)) || !func_contains(pfn, head) )
      {
        bad.push_back(s);
        continue;
      }
      std::string h = hex_str(head);
      if ( std::find(kept.begin(), kept.end(), h) == kept.end() )
        kept.push_back(h);
    }
    std::string what = x.level + " " + (x.cls.empty() ? std::string("finding") : x.cls);
    if ( kept.empty() )
    {
      if ( x.addresses.empty() )
        warnings->push_back("security finding dropped (" + what + "): no address given");
      else
        add_list(warnings, "security finding dropped (" + what + "): no address is an instruction of the function:",
                 x.addresses);
      continue;
    }
    add_list(warnings, "security finding (" + what + "): addresses outside the function ignored:", bad);
    finding_t f = x;
    f.addresses = kept;
    out.push_back(f);
  }
  return out;
}

//------------------------------------------------------------------------------
std::vector<std::string> validate_result(ea_t func_ea, const decomp_result_t &res)
{
  std::vector<std::string> out;
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr )
    return out;

  std::vector<ea_t> notes = code_annotations(res.code);
  std::set<ea_t> uniq(notes.begin(), notes.end());
  qflow_chart_t fc("", pfn, BADADDR, BADADDR, FC_NOEXT);

  // calls: by name, or else by an annotated statement right before each call
  // site (a callee the model renamed, e.g. a COMDAT-folded destructor)
  std::vector<std::string> missing_calls;
  for ( ea_t callee : function_callees(pfn) )
  {
    if ( is_compiler_helper(callee) || is_destructor(callee) )
      continue;
    std::vector<std::string> names = callee_name_variants(callee);
    bool found = is_throw_helper(callee) && has_identifier(res.code, "throw");
    for ( const auto &n : names )
      found |= has_identifier(res.code, n);
    if ( !found )
      found = call_sites_annotated(pfn, callee, uniq, fc);
    if ( !found && !names.empty() )
      missing_calls.push_back(names[0]);
  }
  add_list(&out, "missing calls to", missing_calls);

  // annotations
  if ( notes.empty() )
  {
    out.push_back("the code has no /*0x...*/ address annotations: it cannot be checked against the listing");
    return out;
  }
  std::vector<std::string> outside;
  std::vector<std::string> not_insn;
  for ( ea_t ea : uniq )
  {
    if ( !func_contains(pfn, ea) )
      outside.push_back(hex_str(ea));
    else if ( get_item_head(ea) != ea || !is_code(get_flags(ea)) )
      not_insn.push_back(hex_str(ea));
  }
  add_list(&out, "annotations outside the function:", outside);
  add_list(&out, "annotations that are not an instruction address:", not_insn);

  // coverage
  std::vector<bool> ok(fc.nproper);
  for ( int i = 0; i < fc.nproper; i++ )
  {
    const qbasic_block_t &b = fc.blocks[i];
    auto p = uniq.lower_bound(b.start_ea);
    ok[i] = (p != uniq.end() && *p < b.end_ea) || trivial_block(b.start_ea, b.end_ea);
  }
  // the other tests of 'a || b', the arms of 'c ? x : y' or of a boolean
  // being built: expression pieces reached only from covered blocks or from
  // other such pieces, merged in the statement of the covered block
  for ( bool changed = true; changed; )
  {
    changed = false;
    for ( int i = 0; i < fc.nproper; i++ )
    {
      if ( ok[i] || fc.npred(i) == 0 || !merged_block(fc.blocks[i].start_ea, fc.blocks[i].end_ea) )
        continue;
      bool preds_ok = true;
      for ( int k = 0; k < fc.npred(i); k++ )
      {
        int pr = fc.pred(i, k);
        preds_ok &= pr >= 0 && pr < fc.nproper && ok[pr];
      }
      if ( preds_ok )
      {
        ok[i] = true;
        changed = true;
      }
    }
  }
  std::vector<ea_t> uncovered_eas;
  for ( int i = 0; i < fc.nproper; i++ )
    if ( !ok[i] )
      uncovered_eas.push_back(fc.blocks[i].start_ea);
  std::sort(uncovered_eas.begin(), uncovered_eas.end());
  std::vector<std::string> uncovered;
  for ( ea_t ea : uncovered_eas )
    uncovered.push_back(hex_str(ea));
  if ( !uncovered.empty() )
    add_list(&out, strfmt("%u of %u basic block(s) not covered by any annotation:",
                          unsigned(uncovered.size()), unsigned(fc.nproper)), uncovered);
  return out;
}

} // namespace clauderays
