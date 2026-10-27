// Claude-Rays Decompiler - annotated instruction facts (x86 / x64)
#include "insn_facts.hpp"
#include "insn_table.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#include <cctype>

namespace clauderays
{

static const int MAX_RESULT_SCAN = 12;    // instructions looked at after a call

bool has_insn_facts()
{
  return PH.id == PLFM_386;
}

std::string insn_mnem(ea_t ea)
{
  qstring m;
  if ( !print_insn_mnem(&m, ea) )
    return std::string();
  std::string out = m.c_str();
  for ( auto &c : out )
    c = char(tolower((unsigned char)c));
  return out;
}

static std::string operand_text(ea_t ea, int n)
{
  qstring s;
  if ( !print_operand(&s, ea, n) )
    return std::string();
  qstring clean;
  tag_remove(&clean, s);
  std::string out = clean.c_str();
  for ( auto &c : out )
    c = char(tolower((unsigned char)c));
  return out;
}

static std::string strfmt_addr(ea_t ea)
{
  char buf[32];
  qsnprintf(buf, sizeof(buf), "%" FMT_64 "x", uint64(ea));
  return buf;
}

static std::string line_text(ea_t ea)
{
  qstring s;
  generate_disasm_line(&s, ea, GENDSM_REMOVE_TAGS);
  return s.c_str();
}

static int shown_operands(const insn_t &insn)
{
  int n = 0;
  for ( int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++ )
    n += insn.ops[i].shown() ? 1 : 0;
  return n;
}

// does 'text' contain 'word' delimited by non identifier characters?
static bool has_word(const std::string &text, const char *word)
{
  size_t len = strlen(word);
  for ( size_t p = text.find(word); p != std::string::npos; p = text.find(word, p + 1) )
  {
    bool left = p == 0 || !(isalnum((unsigned char)text[p - 1]) || text[p - 1] == '_');
    bool right = p + len >= text.size() || !(isalnum((unsigned char)text[p + len]) || text[p + len] == '_');
    if ( left && right )
      return true;
  }
  return false;
}

static bool mentions_result_reg(const std::string &text)
{
  for ( const char *r : { "rax", "eax", "ax", "al", "ah", "xmm0", "st", "st(0)" } )
    if ( has_word(text, r) )
      return true;
  return false;
}

static bool is_float_dtype(op_dtype_t dt)
{
  return dt == dt_float || dt == dt_double || dt == dt_tbyte || dt == dt_ldbl;
}

static void add_fact(std::string *facts, const std::string &f)
{
  if ( f.empty() )
    return;
  if ( !facts->empty() )
    *facts += "; ";
  *facts += f;
}

//------------------------------------------------------------------------------
ea_t call_target(ea_t ea)
{
  // a direct call has a code xref to its target
  for ( ea_t t = get_first_fcref_from(ea); t != BADADDR; t = get_next_fcref_from(ea, t) )
    return t;
  // call [import pointer]: the pointer has a name and is in an extern /
  // import segment
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return BADADDR;
  const op_t &op = insn.ops[0];
  if ( op.type == o_mem )
  {
    ea_t p = op.addr;
    segment_t *seg = getseg(p);
    if ( seg != nullptr && (seg->type == SEG_XTRN || seg->type == SEG_IMP) )
      return p;
    flags64_t f = get_flags(p);
    if ( has_name(f) && !is_code(f) )
    {
      qstring n;
      get_name(&n, p);
      if ( n.find("__imp_") == 0 || n.find("_imp_") == 0 )
        return p;
    }
  }
  return BADADDR;
}

//------------------------------------------------------------------------------
// what the code after a call does with the return register
static std::string call_result_use(ea_t call_ea, ea_t end)
{
  ea_t ea = call_ea;
  for ( int i = 0; i < MAX_RESULT_SCAN; i++ )
  {
    ea = next_head(ea, end);
    if ( ea == BADADDR || ea >= end )
      return std::string();
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      return std::string();
    std::string mnem = insn_mnem(ea);
    uint32 feature = insn.get_canon_feature(PH);
    // zeroing idioms write without reading
    if ( (mnem == "xor" || mnem == "sub" || mnem == "pxor" || mnem == "xorps")
      && operand_text(ea, 0) == operand_text(ea, 1)
      && mentions_result_reg(operand_text(ea, 0)) )
    {
      return "result ignored";
    }
    if ( mnem == "cdq" || mnem == "cdqe" || mnem == "cqo" || mnem == "cwde" )
      return "result used";
    // all the operands first: 'mov eax, [rax+20h]' writes eax but reads rax
    bool read = false;
    bool overwritten = false;
    for ( int n = 0; n < UA_MAXOP && insn.ops[n].type != o_void; n++ )
    {
      if ( !insn.ops[n].shown() )
        continue;
      std::string t = operand_text(ea, n);
      if ( !mentions_result_reg(t) )
        continue;
      bool written_only = insn.ops[n].type == o_reg
                       && has_cf_chg(feature, n) && !has_cf_use(feature, n);
      if ( written_only )
        overwritten = true;
      else
        read = true;
    }
    if ( read )
      return "result used";
    if ( overwritten )
      return "result ignored";
    if ( is_call_insn(insn) )
      return "result ignored";
    if ( is_ret_insn(insn) )
      return "result returned";
    if ( (feature & CF_STOP) != 0 )
      return std::string();
  }
  return std::string();
}

static std::string call_facts(const insn_t &insn, const std::string &mnem, ea_t block_end)
{
  std::string facts;
  ea_t ea = insn.ea;
  const op_t &op = insn.ops[0];
  ea_t target = call_target(ea);
  bool tail = mnem == "jmp";
  if ( op.type == o_reg || op.type == o_phrase || op.type == o_displ )
  {
    add_fact(&facts, tail ? "indirect jump" : "indirect call");
  }
  else if ( op.type == o_mem )
  {
    if ( target != BADADDR )
      add_fact(&facts, "through import pointer");
    else
      add_fact(&facts, tail ? "indirect jump through global pointer" : "indirect call through global pointer");
  }
  if ( tail )
  {
    // a jump to another function is a tail call
    func_t *cur = get_func(ea);
    func_t *dst = target != BADADDR ? get_func(target) : nullptr;
    if ( target != BADADDR && cur != nullptr && !func_contains(cur, target)
      && (dst == nullptr || dst->start_ea == target) )
    {
      std::string f = "tail call";
      if ( op.type == o_mem )
        f += " through import pointer";
      facts = f;
    }
    else if ( facts.empty() )
    {
      return std::string();
    }
  }
  if ( target != BADADDR )
  {
    func_t *f = get_func(target);
    bool noret = (f != nullptr && (f->flags & FUNC_NORET) != 0) || !func_does_return(target);
    if ( noret )
      add_fact(&facts, "noreturn");
  }
  if ( !tail )
  {
    // no result to look for when the callee is known to return void
    bool is_void = false;
    tinfo_t tif;
    if ( target != BADADDR && get_tinfo(&tif, target) )
    {
      if ( tif.is_ptr() )
        tif = tif.get_pointed_object();
      is_void = tif.is_func() && tif.get_rettype().is_void();
    }
    if ( !is_void )
      add_fact(&facts, call_result_use(ea, block_end));
  }
  return facts.empty() ? std::string() : "call: " + facts;
}

//------------------------------------------------------------------------------
// the instruction that set the flags read by the conditional instruction at
// 'ea', BADADDR if not in the block
static ea_t find_flag_setter(ea_t ea, ea_t block_start, std::string *mnem)
{
  ea_t p = ea;
  for ( int i = 0; i < 16; i++ )
  {
    p = prev_head(p, block_start);
    if ( p == BADADDR || p < block_start )
      return BADADDR;
    std::string m = insn_mnem(p);
    if ( keeps_flags(m) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, p) <= 0 || is_call_insn(insn) )
      return BADADDR;
    *mnem = m;
    return p;
  }
  return BADADDR;
}

static std::string condition_facts(ea_t ea, const std::string &cc, ea_t block_start)
{
  std::string setter_mnem;
  ea_t setter = find_flag_setter(ea, block_start, &setter_mnem);
  flag_setter_t kind = FS_UNKNOWN;
  if ( setter != BADADDR )
  {
    bool same = setter_mnem == "test" && operand_text(setter, 0) == operand_text(setter, 1);
    kind = classify_flag_setter(setter_mnem, same);
  }
  std::string rel = cc_relation(cc, kind);
  if ( rel.empty() )
    return std::string();
  if ( setter == BADADDR )
    return rel + " (flags from a previous block)";
  if ( kind == FS_UNKNOWN )
    rel += " (flags from the " + setter_mnem + " result)";
  if ( prev_head(ea, block_start) != setter )
    rel += " (flags set at " + strfmt_addr(setter) + ")";
  return rel;
}

//------------------------------------------------------------------------------
static std::string memory_facts(const insn_t &insn, const std::string &mnem)
{
  if ( mnem == "lea" || mnem.compare(0, 3, "nop") == 0 || mnem.compare(0, 8, "prefetch") == 0
    || mnem == "clflush" )
  {
    return std::string();
  }
  std::string facts;
  int ext = extension_kind(mnem);
  uint32 feature = insn.get_canon_feature(PH);
  for ( int n = 0; n < UA_MAXOP && insn.ops[n].type != o_void; n++ )
  {
    const op_t &op = insn.ops[n];
    if ( !op.shown() )
      continue;
    bool is_mem = op.type == o_mem || op.type == o_phrase || op.type == o_displ;
    size_t size = get_dtype_size(op.dtype);
    if ( is_mem )
    {
      bool use = has_cf_use(feature, n);
      bool chg = has_cf_chg(feature, n);
      const char *access = use && chg ? "load+store" : chg ? "store" : "load";
      std::string f = std::string(access) + " " + size_name(size, ext, is_float_dtype(op.dtype));
      if ( ext == 1 )
        f += ", sign-extend";
      else if ( ext == 2 )
        f += ", zero-extend";
      add_fact(&facts, f);
    }
    else if ( op.type == o_reg && ext != 0 && n > 0 )
    {
      add_fact(&facts, (ext == 1 ? "sign-extend " : "zero-extend ") + size_name(size, ext, false));
    }
  }
  return facts;
}

static std::string constant_facts(const insn_t &insn, const std::string &mnem)
{
  std::string facts;
  flags64_t flags = get_flags(insn.ea);
  for ( int n = 0; n < UA_MAXOP && insn.ops[n].type != o_void; n++ )
  {
    const op_t &op = insn.ops[n];
    if ( op.type != o_imm || !op.shown() )
      continue;
    if ( is_off(flags, n) || is_enum(flags, n) || is_stroff(flags, n) || is_char(flags, n) )
      continue;
    uint64 v = op.value;
    size_t size = get_dtype_size(op.dtype);
    if ( size > 0 && size < 8 )
      v &= (uint64(1) << (size * 8)) - 1;
    // a constant that is the address of a named item
    ea_t a = ea_t(v);
    if ( v >= 0x10000 && is_mapped(a) )
    {
      qstring name;
      if ( get_name(&name, a) > 0 )
      {
        add_fact(&facts, "address of " + std::string(name.c_str()));
        continue;
      }
    }
    if ( mnem == "and" || mnem == "or" || mnem == "xor" || mnem == "test"
      || mnem == "shl" || mnem == "shr" || mnem == "sar" || mnem == "rol" || mnem == "ror" )
    {
      continue;
    }
    // single characters only where a character is likely
    bool single = v < 0x100;
    if ( single && !(mnem == "cmp" || mnem == "sub" || mnem == "mov" || mnem == "push" || size == 1) )
      continue;
    add_fact(&facts, ascii_constant(v, size == 0 ? 8 : size));
  }
  return facts;
}

//------------------------------------------------------------------------------
std::string insn_facts_at(ea_t ea, ea_t block_start, ea_t block_end)
{
  if ( !has_insn_facts() || !is_code(get_flags(ea)) )
    return std::string();
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return std::string();
  std::string mnem = insn_mnem(ea);
  std::string facts;
  std::string cc = condition_code(mnem);
  if ( !cc.empty() )
    add_fact(&facts, condition_facts(ea, cc, block_start));
  if ( is_call_insn(insn) || mnem == "jmp" )
  {
    add_fact(&facts, call_facts(insn, mnem, block_end));
  }
  else
  {
    add_fact(&facts, memory_facts(insn, mnem));
    add_fact(&facts, constant_facts(insn, mnem));
  }
  std::string text = line_text(ea);
  size_t b = text.find_first_not_of(" \t");
  bool rep = b != std::string::npos && text.compare(b, 3, "rep") == 0;
  add_fact(&facts, mnemonic_fact(mnem, shown_operands(insn), rep));
  return facts;
}

void block_insn_facts(ea_t start, ea_t end, std::map<ea_t, std::string> *out)
{
  if ( !has_insn_facts() )
    return;
  for ( ea_t ea = start; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    std::string facts = insn_facts_at(ea, start, end);
    if ( !facts.empty() )
      (*out)[ea] = facts;
  }
}

} // namespace clauderays
