// Claude-Rays Decompiler - context collector
#include "collector.hpp"
#include "insn_facts.hpp"

#include <bytes.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <map>

namespace clauderays
{

static const size_t SMALL_CALLEE_INSNS = 30;    // listed in full below this
static const size_t MAX_SMALL_CALLEES = 12;
static const size_t MAX_CALLERS = 3;
static const size_t MAX_CALLER_NAMES = 8;
static const int CALL_SITE_INSNS = 6;           // without a prototype
static const size_t MAX_DATA_ITEMS = 60;
static const size_t MAX_STRING_LEN = 300;
static const size_t MAX_COMMENT_LEN = 300;
static const size_t MAX_TYPE_LEN = 3000;
static const size_t MAX_TYPES = 20;
static const size_t MAX_REQUESTS = 5;
static const size_t MAX_DATA_XREFS = 10;
static const size_t MAX_REQUESTED_INSNS = 400;  // a requested function listing
static const int FACTS_COLUMN = 48;

//------------------------------------------------------------------------------
// sections and the budget
//------------------------------------------------------------------------------
struct section_t
{
  std::string title;
  std::string intro;                  // text before the items (never trimmed)
  std::vector<std::string> items;     // trimmed from the end
  int trim_rank = 0;                  // 0 = untouchable; the highest goes first
  size_t dropped = 0;

  size_t size() const
  {
    size_t n = title.size() + intro.size() + 16;
    for ( const auto &i : items )
      n += i.size() + 1;
    return n;
  }
  std::string render() const
  {
    if ( intro.empty() && items.empty() )
      return std::string();
    std::string out = "== " + title + " ==\n" + intro;
    if ( !intro.empty() && intro.back() != '\n' )
      out += "\n";
    for ( const auto &i : items )
    {
      out += i;
      if ( i.empty() || i.back() != '\n' )
        out += "\n";
    }
    if ( dropped != 0 )
      out += strfmt("(%u more left out for size)\n", unsigned(dropped));
    return out + "\n";
  }
};

static std::string assemble(std::vector<section_t> &sections, size_t budget, collected_t *out)
{
  auto total = [&]()
  {
    size_t n = 0;
    for ( const auto &s : sections )
      n += s.size();
    return n;
  };
  // trim the sections with the highest rank first, one item at a time
  while ( total() > budget )
  {
    section_t *victim = nullptr;
    for ( auto &s : sections )
      if ( s.trim_rank > 0 && !s.items.empty() && (victim == nullptr || s.trim_rank > victim->trim_rank) )
        victim = &s;
    if ( victim == nullptr )
      break;
    victim->items.pop_back();
    victim->dropped++;
  }
  std::string text;
  for ( const auto &s : sections )
  {
    std::string r = s.render();
    if ( out != nullptr )
      out->sizes.push_back({ s.title, r.size() });
    text += r;
  }
  return text;
}

//------------------------------------------------------------------------------
// small helpers
//------------------------------------------------------------------------------
static std::string func_name(ea_t ea)
{
  qstring n;
  get_func_name(&n, ea);
  return n.empty() ? ea_name(ea) : std::string(n.c_str());
}

// regular and repeatable function comments, on one line
static std::string func_comment(ea_t ea)
{
  qstring cmt;
  qstring rcmt;
  std::string out;
  if ( get_func_cmt_ea(&cmt, ea, false) > 0 )
    out = cmt.c_str();
  if ( get_func_cmt_ea(&rcmt, ea, true) > 0 && rcmt != cmt )
    out += (out.empty() ? "" : " / ") + std::string(rcmt.c_str());
  return one_line(out, MAX_COMMENT_LEN);
}

static std::string disasm_line(ea_t ea)
{
  qstring s;
  generate_disasm_line(&s, ea, GENDSM_REMOVE_TAGS);
  return trim(s.c_str());
}

// the prototype of 'ea': the one in the database or one guessed by IDA
static std::string prototype_of(ea_t ea, bool *known)
{
  *known = false;
  tinfo_t tif;
  qstring out;
  std::string name = func_name(ea);
  if ( get_tinfo(&tif, ea) )
  {
    // import pointers are typed as pointers to the function
    if ( tif.is_ptr() && tif.get_pointed_object().is_func() )
      tif = tif.get_pointed_object();
    if ( tif.is_func() )
    {
      *known = true;
      tif.print(&out, name.c_str(), PRTYPE_1LINE);
      return one_line(out.c_str(), 400);
    }
  }
  if ( get_func(ea) != nullptr && guess_tinfo(&tif, ea) == GUESS_FUNC_OK && tif.is_func() )
  {
    tif.print(&out, name.c_str(), PRTYPE_1LINE);
    return one_line(out.c_str(), 400);
  }
  return std::string();
}

size_t count_insns(func_t *pfn)
{
  size_t n = 0;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
    n++;
  return n;
}

//------------------------------------------------------------------------------
// types used by the function, printed once in the Types section
//------------------------------------------------------------------------------
struct type_set_t
{
  std::vector<std::string> names;     // in discovery order
  std::set<std::string> seen;

  void add(tinfo_t t)
  {
    for ( int guard = 0; guard < 8; guard++ )
    {
      if ( t.is_ptr() )
        t = t.get_pointed_object();
      else if ( t.is_array() )
        t = t.get_array_element();
      else
        break;
    }
    if ( t.is_func() )
    {
      func_type_data_t fi;
      if ( t.get_func_details(&fi) )
      {
        add_simple(fi.rettype);
        for ( const auto &a : fi )
          add_simple(a.type);
      }
      return;
    }
    add_simple(t);
  }
  void add_simple(tinfo_t t)
  {
    for ( int guard = 0; guard < 8 && (t.is_ptr() || t.is_array()); guard++ )
      t = t.is_ptr() ? t.get_pointed_object() : t.get_array_element();
    if ( !t.is_udt() && !t.is_enum() )
      return;
    qstring name;
    if ( !t.get_type_name(&name) || name.empty() )
      return;
    if ( seen.insert(name.c_str()).second )
      names.push_back(name.c_str());
  }
  void add_tid(tid_t tid)
  {
    tinfo_t t;
    if ( tid != BADADDR && t.get_type_by_tid(tid) )
      add_simple(t);
  }
};

static std::string type_definition(const std::string &name)
{
  tinfo_t t;
  if ( !t.get_named_type(get_idati(), name.c_str()) )
    return std::string();
  qstring out;
  if ( !t.print(&out, nullptr, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI) )
    return std::string();
  std::string s = out.c_str();
  if ( s.size() > MAX_TYPE_LEN )
    s = s.substr(0, MAX_TYPE_LEN) + "\n  ... (cut)";
  return s;
}

//------------------------------------------------------------------------------
// the control flow graph: blocks, kinds, loops (dominators)
//------------------------------------------------------------------------------
struct cfg_t
{
  qflow_chart_t fc;
  std::vector<int> order;             // proper blocks by address
  std::map<int, int> number;          // fc index -> displayed number
  std::vector<int> idom;
  std::vector<std::vector<int>> back_edges_from;   // per header
  std::vector<std::vector<int>> loops_of;          // headers containing a block
  std::vector<bool> reachable;

  explicit cfg_t(func_t *pfn) : fc("", pfn, BADADDR, BADADDR, 0)
  {
    int n = fc.nproper;
    for ( int i = 0; i < n; i++ )
      order.push_back(i);
    std::sort(order.begin(), order.end(),
              [&](int a, int b) { return fc.blocks[a].start_ea < fc.blocks[b].start_ea; });
    for ( size_t i = 0; i < order.size(); i++ )
      number[order[i]] = int(i);
    compute_loops(pfn->start_ea);
  }

  int entry_block(ea_t ea) const
  {
    for ( int i = 0; i < fc.nproper; i++ )
      if ( fc.blocks[i].contains(ea) )
        return i;
    return -1;
  }

  // Cooper, Harvey, Kennedy: "A Simple, Fast Dominance Algorithm"
  void compute_loops(ea_t entry_ea)
  {
    int n = fc.nproper;
    idom.assign(n, -1);
    back_edges_from.assign(n, {});
    loops_of.assign(n, {});
    reachable.assign(n, false);
    int entry = entry_block(entry_ea);
    if ( entry < 0 )
      return;

    // reverse post order from the entry
    std::vector<int> post;
    std::vector<int> state(n, 0);
    std::vector<std::pair<int, int>> stack;
    stack.push_back({ entry, 0 });
    state[entry] = 1;
    while ( !stack.empty() )
    {
      int b = stack.back().first;
      int &i = stack.back().second;
      if ( i < int(fc.blocks[b].succ.size()) )
      {
        int s = fc.blocks[b].succ[i++];
        if ( s < n && state[s] == 0 )
        {
          state[s] = 1;
          stack.push_back({ s, 0 });
        }
        continue;
      }
      post.push_back(b);
      stack.pop_back();
    }
    std::vector<int> rpo_num(n, -1);
    std::vector<int> rpo(post.rbegin(), post.rend());
    for ( size_t i = 0; i < rpo.size(); i++ )
    {
      rpo_num[rpo[i]] = int(i);
      reachable[rpo[i]] = true;
    }

    auto intersect = [&](int a, int b)
    {
      while ( a != b )
      {
        while ( rpo_num[a] > rpo_num[b] )
          a = idom[a];
        while ( rpo_num[b] > rpo_num[a] )
          b = idom[b];
      }
      return a;
    };
    idom[entry] = entry;
    for ( bool changed = true; changed; )
    {
      changed = false;
      for ( size_t i = 1; i < rpo.size(); i++ )
      {
        int b = rpo[i];
        int new_idom = -1;
        for ( int p : fc.blocks[b].pred )
        {
          if ( p >= n || idom[p] < 0 )
            continue;
          new_idom = new_idom < 0 ? p : intersect(p, new_idom);
        }
        if ( new_idom >= 0 && idom[b] != new_idom )
        {
          idom[b] = new_idom;
          changed = true;
        }
      }
    }

    // back edges u -> h where h dominates u, and the natural loop of each
    for ( int u : rpo )
    {
      for ( int h : fc.blocks[u].succ )
      {
        if ( h >= n || !reachable[h] || !dominates(h, u) )
          continue;
        back_edges_from[h].push_back(u);
        std::set<int> body = { h };
        std::vector<int> work;
        if ( body.insert(u).second )
          work.push_back(u);
        while ( !work.empty() )
        {
          int x = work.back();
          work.pop_back();
          for ( int p : fc.blocks[x].pred )
            if ( p < n && reachable[p] && body.insert(p).second )
              work.push_back(p);
        }
        for ( int x : body )
          if ( std::find(loops_of[x].begin(), loops_of[x].end(), h) == loops_of[x].end() )
            loops_of[x].push_back(h);
      }
    }
  }

  bool dominates(int a, int b) const
  {
    for ( int guard = 0; guard < fc.nproper + 1; guard++ )
    {
      if ( b == a )
        return true;
      if ( b < 0 || idom[b] == b )
        return false;
      b = idom[b];
    }
    return false;
  }

  std::string block_header(int b) const
  {
    const qbasic_block_t &blk = fc.blocks[b];
    std::string label = ea_name(blk.start_ea);
    if ( label.empty() )
      label = "block_" + addr_str(blk.start_ea);
    std::string info = strfmt("block %d", number.at(b));
    switch ( fc.calc_block_type(b) )
    {
      case fcb_ret:     info += ", return"; break;
      case fcb_cndret:  info += ", conditional return"; break;
      case fcb_noret:   info += ", noreturn"; break;
      case fcb_enoret:  info += ", noreturn"; break;
      case fcb_indjump: info += ", indirect jump"; break;
      case fcb_error:   info += ", runs past the function end"; break;
      default: break;
    }
    if ( !reachable[b] )
      info += ", unreachable from the entry";
    if ( !back_edges_from[b].empty() )
    {
      info += ", loop header (back edge from ";
      for ( size_t i = 0; i < back_edges_from[b].size(); i++ )
      {
        // the address of the jump that closes the loop
        const qbasic_block_t &src = fc.blocks[back_edges_from[b][i]];
        ea_t last = prev_head(src.end_ea, src.start_ea);
        info += (i == 0 ? "" : ", ") + hex_str(last == BADADDR ? src.start_ea : last);
      }
      info += ")";
    }
    std::string in_loops;
    for ( int h : loops_of[b] )
      if ( h != b )
        in_loops += (in_loops.empty() ? "" : ", ") + hex_str(fc.blocks[h].start_ea);
    if ( !in_loops.empty() )
      info += ", in loop " + in_loops;
    std::string succ;
    for ( int s : blk.succ )
    {
      std::string t = s < fc.nproper ? strfmt("%d", number.at(s))
                                     : "outside " + hex_str(fc.blocks[s].start_ea);
      succ += (succ.empty() ? "" : ", ") + t;
    }
    if ( !succ.empty() )
      info += ", -> " + succ;
    std::string line = label + ":";
    if ( line.size() < 36 )
      line.append(36 - line.size(), ' ');
    return line + " ; " + info;
  }
};

//------------------------------------------------------------------------------
// the annotated listing
//------------------------------------------------------------------------------
static std::string listing_line(ea_t ea, const std::string &facts)
{
  std::string line = "  " + addr_str(ea) + "  " + disasm_line(ea);
  if ( !facts.empty() )
  {
    if ( int(line.size()) < FACTS_COLUMN )
      line.append(FACTS_COLUMN - line.size(), ' ');
    line += " ; " + facts;
  }
  return line;
}

// the listing of a whole function by basic blocks, also collecting the types
// and data it uses
static std::string function_listing(func_t *pfn, type_set_t *types)
{
  cfg_t cfg(pfn);
  std::string out;
  for ( int b : cfg.order )
  {
    const qbasic_block_t &blk = cfg.fc.blocks[b];
    out += cfg.block_header(b) + "\n";
    std::map<ea_t, std::string> facts;
    block_insn_facts(blk.start_ea, blk.end_ea, &facts);
    for ( ea_t ea = blk.start_ea; ea != BADADDR && ea < blk.end_ea; ea = next_head(ea, blk.end_ea) )
    {
      flags64_t f = get_flags(ea);
      if ( !is_code(f) )
        continue;
      auto p = facts.find(ea);
      out += listing_line(ea, p != facts.end() ? p->second : std::string()) + "\n";
      if ( types != nullptr )
      {
        // struct offsets and enums in the operands
        for ( int n = 0; n < UA_MAXOP; n++ )
        {
          if ( is_stroff(f, n) )
          {
            tid_t path[MAXSTRUCPATH];
            adiff_t delta = 0;
            int len = get_stroff_path(path, &delta, ea, n);
            for ( int i = 0; i < len; i++ )
              types->add_tid(path[i]);
          }
          if ( is_enum(f, n) )
          {
            uchar serial = 0;
            types->add_tid(get_enum_id(&serial, ea, n));
          }
        }
      }
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// sections
//------------------------------------------------------------------------------
static std::string arch_text()
{
  qstring proc = inf_get_procname();
  std::string out = proc.c_str();
  out += inf_is_64bit() ? ", 64-bit" : inf_is_32bit_exactly() ? ", 32-bit" : ", 16-bit";
  out += inf_is_be() ? ", big endian" : ", little endian";
  char ftype[256];
  if ( get_file_type_name(ftype, sizeof(ftype)) > 0 )
    out += std::string(", file: ") + ftype;
  comp_t cc = inf_get_cc_id();
  if ( cc != COMP_UNK )
    out += std::string(", compiler: ") + get_compiler_name(cc);
  return out;
}

static section_t header_section(func_t *pfn, size_t ninsns, size_t nblocks, type_set_t *types)
{
  section_t s;
  s.title = "Function";
  ea_t ea = pfn->start_ea;
  std::string &t = s.intro;
  t += "Name: " + func_name(ea) + (has_user_name(get_flags(ea)) ? " (set by the analyst or the binary)" : " (default name)") + "\n";
  t += "Address: " + hex_str(ea) + " - " + hex_str(pfn->end_ea);
  int nchunks = 0;
  func_tail_iterator_t fti(pfn);
  for ( bool ok = fti.main(); ok; ok = fti.next() )
    nchunks++;
  if ( nchunks > 1 )
    t += strfmt(" (%d chunks)", nchunks);
  t += "\n";
  t += "Architecture: " + arch_text() + "\n";
  bool known = false;
  std::string proto = prototype_of(ea, &known);
  if ( !proto.empty() )
    t += "Prototype: " + proto + (known ? " (from the database)" : " (guessed by IDA, may be wrong)") + "\n";
  tinfo_t tif;
  if ( get_tinfo(&tif, ea) )
    types->add(tif);
  if ( (pfn->flags & FUNC_NORET) != 0 )
    t += "Returns: no (noreturn function)\n";
  if ( (pfn->flags & FUNC_LIB) != 0 )
    t += "Library function (recognized by FLIRT)\n";
  if ( (pfn->flags & FUNC_THUNK) != 0 )
    t += "Thunk function\n";
  std::string cmt = func_comment(ea);
  if ( !cmt.empty() )
    t += "Comment: " + cmt + "\n";
  t += strfmt("Size: %u instructions, %u basic blocks\n", unsigned(ninsns), unsigned(nblocks));
  return s;
}

static section_t frame_section(func_t *pfn, type_set_t *types)
{
  section_t s;
  s.title = "Stack frame";
  tinfo_t frame;
  if ( !get_func_frame(&frame, pfn->start_ea) )
    return s;
  udt_type_data_t udt;
  if ( !frame.get_udt_details(&udt) )
    return s;
  s.intro = strfmt("Locals 0x%" FMT_64 "x bytes, saved registers 0x%x bytes, purged arguments 0x%" FMT_64 "x bytes%s. "
                   "Offsets are from the frame pointer position (negative: locals, positive: arguments).\n",
                   uint64(pfn->frsize), unsigned(pfn->frregs), uint64(pfn->argsize),
                   (pfn->flags & FUNC_FRAME) != 0 ? ", uses a frame pointer" : "");
  ea_t args_off = frame_off_args_ea(pfn->start_ea);
  for ( const udm_t &m : udt )
  {
    if ( m.name == FRAME_UDM_NAME_R || m.name == FRAME_UDM_NAME_S || m.is_gap() )
      continue;
    uint64 off = m.offset / 8;
    sval_t fpoff = soff_to_fpoff_ea(pfn->start_ea, uval_t(off));
    qstring type;
    m.type.print(&type);
    types->add(m.type);
    std::string line = strfmt("  %-20s %s0x%" FMT_64 "x  size %" FMT_64 "u  %s%s",
                              m.name.c_str(), fpoff < 0 ? "-" : "+",
                              uint64(fpoff < 0 ? -fpoff : fpoff), uint64(m.size / 8),
                              type.c_str(), off >= args_off ? "  (argument)" : "");
    if ( !m.cmt.empty() )
      line += "  // " + one_line(m.cmt.c_str(), MAX_COMMENT_LEN);
    s.items.push_back(line);
  }
  if ( s.items.empty() )
    s.intro.clear();
  return s;
}

static section_t switch_section(func_t *pfn, const cfg_t &cfg)
{
  section_t s;
  s.title = "Switch";
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
  {
    ea_t ea = fii.current();
    switch_info_t si;
    if ( get_switch_info(&si, ea) <= 0 )
      continue;
    std::string t = "switch at " + hex_str(ea);
    if ( si.startea != BADADDR && si.startea != ea )
      t += " (idiom starts at " + hex_str(si.startea) + ")";
    if ( si.regnum >= 0 )
    {
      qstring reg;
      if ( get_reg_name(&reg, si.regnum, get_dtype_size(si.regdtype)) > 0 )
        t += " on " + std::string(reg.c_str());
    }
    t += strfmt(": %u cases", unsigned(si.ncases));
    if ( !si.is_sparse() )
      t += strfmt(", lowest case %" FMT_64 "d", int64(si.get_lowcase()));
    t += si.has_default() ? ", default -> " + hex_str(si.defjump) : std::string(", no default");
    if ( si.jumps != BADADDR )
      t += strfmt(", jump table at %s (%d-byte entries)", hex_str(si.jumps).c_str(),
                  si.get_jtable_element_size());
    t += "\n";
    casevec_t cases;
    eavec_t targets;
    if ( calc_switch_cases(&cases, &targets, ea, si) )
    {
      // targets with the same address are merged
      std::map<ea_t, std::vector<sval_t>> by_target;
      std::vector<ea_t> target_order;
      for ( size_t i = 0; i < targets.size() && i < cases.size(); i++ )
      {
        if ( by_target.count(targets[i]) == 0 )
          target_order.push_back(targets[i]);
        for ( sval_t v : cases[i] )
          by_target[targets[i]].push_back(v);
      }
      for ( ea_t target : target_order )
      {
        std::string vals;
        for ( sval_t v : by_target[target] )
          vals += (vals.empty() ? "" : ", ") + strfmt("%" FMT_64 "d", int64(v));
        int blk = -1;
        for ( int b : cfg.order )
          if ( cfg.fc.blocks[b].contains(target) )
            blk = cfg.number.at(b);
        t += "  case " + vals + " -> " + hex_str(target);
        if ( blk >= 0 )
          t += strfmt(" (block %d)", blk);
        if ( target == si.defjump )
          t += " (also the default)";
        t += "\n";
      }
    }
    s.items.push_back(t);
  }
  return s;
}

// the functions called by 'pfn' in order of appearance (tail calls too)
std::vector<ea_t> function_callees(func_t *pfn)
{
  std::vector<ea_t> out;
  std::set<ea_t> seen;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_code() )
  {
    ea_t ea = fii.current();
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      continue;
    bool is_jump = (insn.get_canon_feature(PH) & CF_STOP) != 0 && !is_ret_insn(insn);
    if ( !is_call_insn(insn) && !is_jump )
      continue;
    ea_t t = call_target(ea);
    if ( t == BADADDR || t == pfn->start_ea )
      continue;
    // a jump is a call only when it leaves the function for another one
    if ( !is_call_insn(insn) && (func_contains(pfn, t) || (get_func(t) != nullptr && get_func(t)->start_ea != t)) )
      continue;
    if ( seen.insert(t).second )
      out.push_back(t);
  }
  return out;
}

static void callee_sections(func_t *pfn, type_set_t *types, section_t *protos, section_t *small)
{
  protos->title = "Called functions";
  small->title = "Listings of small unnamed callees";
  small->trim_rank = 4;
  for ( ea_t t : function_callees(pfn) )
  {
    std::string name = ea_name(t);
    func_t *f = get_func(t);
    bool known = false;
    std::string proto = prototype_of(t, &known);
    std::string line = "  " + hex_str(t) + "  " + (proto.empty() ? name : proto);
    if ( !proto.empty() && !known )
      line += "  (prototype guessed by IDA)";
    tinfo_t tif;
    if ( get_tinfo(&tif, t) )
      types->add(tif);
    segment_t *seg = getseg(t);
    if ( seg != nullptr && (seg->type == SEG_XTRN || seg->type == SEG_IMP) )
      line += "  [import]";
    if ( f != nullptr )
    {
      if ( (f->flags & FUNC_NORET) != 0 )
        line += "  [noreturn]";
      if ( (f->flags & FUNC_LIB) != 0 )
        line += "  [library]";
      if ( (f->flags & FUNC_THUNK) != 0 )
      {
        ea_t target = BADADDR;
        ea_t thunk_to = calc_thunk_func_target(f, &target);
        if ( thunk_to != BADADDR )
          line += "  [thunk to " + ea_name(thunk_to) + "]";
      }
      std::string cmt = func_comment(t);
      if ( !cmt.empty() )
        line += "  // " + cmt;
    }
    protos->items.push_back(line);

    // small functions without a name: their whole listing, one level deep
    if ( f != nullptr && f->start_ea == t && !has_user_name(get_flags(t))
      && (f->flags & (FUNC_LIB | FUNC_THUNK)) == 0
      && small->items.size() < MAX_SMALL_CALLEES )
    {
      size_t n = count_insns(f);
      if ( n < SMALL_CALLEE_INSNS )
      {
        std::string head = "-- " + name + " (" + hex_str(t) + ", " + strfmt("%u instructions", unsigned(n)) + ")";
        if ( !proto.empty() )
          head += ": " + proto;
        small->items.push_back(head + "\n" + function_listing(f, nullptr));
      }
    }
  }
}

static section_t call_site_section(func_t *pfn)
{
  section_t s;
  s.title = "Call sites";
  s.trim_rank = 3;
  ea_t func_ea = pfn->start_ea;
  // the calls, grouped by calling function
  std::vector<ea_t> callers;
  std::map<ea_t, ea_t> first_site;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(func_ea, XREF_CODE | XREF_NOFLOW); ok; ok = xb.next_to() )
  {
    if ( xb.type != fl_CN && xb.type != fl_CF )
      continue;
    func_t *f = get_func(xb.from);
    if ( f == nullptr || f->start_ea == func_ea )
      continue;
    if ( first_site.count(f->start_ea) == 0 )
    {
      callers.push_back(f->start_ea);
      first_site[f->start_ea] = xb.from;
    }
  }
  if ( callers.empty() )
    return s;
  std::string names;
  for ( size_t i = 0; i < callers.size() && i < MAX_CALLER_NAMES; i++ )
    names += (i == 0 ? "" : ", ") + func_name(callers[i]);
  if ( callers.size() > MAX_CALLER_NAMES )
    names += strfmt(" and %u more", unsigned(callers.size() - MAX_CALLER_NAMES));
  s.intro = strfmt("Called by %u function(s): ", unsigned(callers.size())) + names + "\n";

  for ( size_t i = 0; i < callers.size() && i < MAX_CALLERS; i++ )
  {
    ea_t site = first_site[callers[i]];
    func_t *caller = get_func(site);
    std::vector<ea_t> lines;
    eavec_t args;
    if ( get_arg_addrs(&args, site) )
    {
      for ( ea_t a : args )
        if ( a != BADADDR )
          lines.push_back(a);
      std::sort(lines.begin(), lines.end());
    }
    else
    {
      ea_t p = site;
      for ( int k = 0; k < CALL_SITE_INSNS; k++ )
      {
        p = prev_head(p, caller->start_ea);
        if ( p == BADADDR || !func_contains(caller, p) )
          break;
        lines.insert(lines.begin(), p);
      }
    }
    lines.push_back(site);
    // the result use is the fact of the call instruction itself
    func_t *chunk = get_fchunk(site);
    ea_t end = chunk != nullptr ? chunk->end_ea : caller->end_ea;
    std::string t = "in " + func_name(caller->start_ea) + " at " + hex_str(site) + ":\n";
    for ( ea_t a : lines )
      t += listing_line(a, a == site ? insn_facts_at(a, a, end) : std::string()) + "\n";
    s.items.push_back(t);
  }
  return s;
}

// the string literal at 'ea', "" if there is none
static std::string strlit_at(ea_t ea)
{
  if ( !is_strlit(get_flags(ea)) )
    return std::string();
  qstring s;
  if ( get_strlit_contents(&s, ea, get_item_size(ea), get_str_type(ea)) <= 0 )
    return std::string();
  return s.c_str();
}

static std::string quote(const std::string &s)
{
  std::string out = "\"";
  for ( char c : s )
  {
    if ( c == '\n' )
      out += "\\n";
    else if ( c == '\r' )
      out += "\\r";
    else if ( c == '\t' )
      out += "\\t";
    else if ( c == '"' || c == '\\' )
      out += std::string("\\") + c;
    else
      out += c;
  }
  return out + "\"";
}

// a description of the data at 'ea' on one line, "" for code / imports
static std::string describe_data(ea_t ea, type_set_t *types)
{
  flags64_t f = get_flags(ea);
  segment_t *seg = getseg(ea);
  if ( seg != nullptr && (seg->type == SEG_XTRN || seg->type == SEG_IMP) )
    return std::string();
  if ( is_code(f) )
  {
    func_t *fn = get_func(ea);
    if ( fn != nullptr && fn->start_ea == ea )
      return hex_str(ea) + "  address of the function " + func_name(ea);
    return std::string();
  }
  ea_t head = get_item_head(ea);
  flags64_t hf = get_flags(head);
  std::string name = ea_name(head);
  std::string where = name.empty() ? hex_str(head) : name + " (" + hex_str(head) + ")";
  if ( head != ea )
    where += strfmt(" + 0x%" FMT_64 "x", uint64(ea - head));
  qstring segname;
  if ( seg != nullptr )
    get_segm_name(&segname, seg);

  std::string text = strlit_at(head);
  if ( !text.empty() )
    return where + "  string " + one_line(quote(text), MAX_STRING_LEN);

  std::string out = where;
  if ( !segname.empty() )
    out += "  [" + std::string(segname.c_str()) + "]";
  tinfo_t tif;
  if ( get_tinfo(&tif, head) )
  {
    qstring t;
    tif.print(&t);
    out += "  type " + std::string(t.c_str());
    types->add(tif);
  }
  asize_t size = get_item_size(head);
  if ( size == 0 )
    size = 1;
  if ( !is_loaded(head) )
    return out + strfmt("  size %" FMT_64 "u, uninitialized (bss)", uint64(size));
  size_t ptrsize = inf_is_64bit() ? 8 : 4;
  if ( is_off0(hf) && size == ptrsize )
  {
    ea_t p = ptrsize == 8 ? ea_t(get_qword(head)) : ea_t(get_dword(head));
    out += "  pointer to " + hex_str(p);
    std::string pn = ea_name(p);
    if ( !pn.empty() )
      out += " " + pn;
    std::string s = strlit_at(p);
    if ( !s.empty() )
      out += " = string " + one_line(quote(s), MAX_STRING_LEN);
    return out;
  }
  if ( size == 1 || size == 2 || size == 4 || size == 8 )
  {
    uint64 v = size == 1 ? get_byte(head) : size == 2 ? get_word(head)
             : size == 4 ? get_dword(head) : get_qword(head);
    if ( is_float(hf) && size == 4 )
    {
      uint32 u = uint32(v);
      float x;
      memcpy(&x, &u, 4);
      return out + strfmt("  value %g", double(x));
    }
    if ( is_double(hf) && size == 8 )
    {
      double x;
      memcpy(&x, &v, 8);
      return out + strfmt("  value %g", x);
    }
    return out + strfmt("  size %u, value 0x%" FMT_64 "x", unsigned(size), v);
  }
  // first bytes of a larger item
  size_t n = size_t(qmin(size, asize_t(32)));
  bytevec_t bytes;
  bytes.resize(n);
  get_bytes(bytes.begin(), n, head);
  out += strfmt("  size %" FMT_64 "u, bytes", uint64(size));
  for ( size_t i = 0; i < n; i++ )
    out += strfmt(" %02x", bytes[i]);
  if ( size > n )
    out += " ...";
  return out;
}

static section_t data_section(func_t *pfn, type_set_t *types)
{
  section_t s;
  s.title = "Data";
  s.trim_rank = 1;
  std::set<ea_t> seen;
  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok && s.items.size() < MAX_DATA_ITEMS; ok = fii.next_code() )
  {
    ea_t head = fii.current();
    for ( ea_t x = get_first_dref_from(head); x != BADADDR; x = get_next_dref_from(head, x) )
    {
      if ( func_contains(pfn, x) && is_code(get_flags(x)) )
        continue;
      if ( !seen.insert(x).second )
        continue;
      std::string d = describe_data(x, types);
      if ( !d.empty() )
        s.items.push_back("  " + d);
    }
  }
  return s;
}

static section_t types_section(const type_set_t &types)
{
  section_t s;
  s.title = "Types";
  s.trim_rank = 2;
  for ( const auto &name : types.names )
  {
    if ( s.items.size() >= MAX_TYPES )
      break;
    std::string def = type_definition(name);
    if ( !def.empty() )
      s.items.push_back(def);
  }
  return s;
}

//------------------------------------------------------------------------------
bool collect_function_context(ea_t func_ea, collected_t *out, size_t budget)
{
  func_t *pfn = get_func(func_ea);
  if ( pfn == nullptr )
  {
    out->error = "the cursor is not in a function";
    return false;
  }
  out->ninsns = count_insns(pfn);
  if ( out->ninsns > size_t(settings().max_insns) )
  {
    out->error = strfmt("%s has %u instructions, more than the limit of %d (Claude-Rays Decompiler/Settings): "
                        "large functions are not sent yet",
                        func_name(pfn->start_ea).c_str(), unsigned(out->ninsns), settings().max_insns);
    return false;
  }

  type_set_t types;
  cfg_t cfg(pfn);
  std::vector<section_t> sections;
  sections.push_back(header_section(pfn, out->ninsns, cfg.order.size(), &types));
  sections.push_back(frame_section(pfn, &types));

  section_t listing;
  listing.title = "Listing";
  listing.intro = has_insn_facts()
    ? "Annotated disassembly by basic block ('; ' facts at the end of the lines are exact).\n"
    : "Disassembly by basic block (no instruction facts for this processor).\n";
  listing.items.push_back(function_listing(pfn, &types));
  sections.push_back(listing);

  sections.push_back(switch_section(pfn, cfg));
  section_t protos;
  section_t small;
  callee_sections(pfn, &types, &protos, &small);
  sections.push_back(protos);
  sections.push_back(small);
  sections.push_back(call_site_section(pfn));
  sections.push_back(data_section(pfn, &types));
  sections.push_back(types_section(types));

  out->body = assemble(sections, budget != 0 ? budget : size_t(settings().budget), out);
  out->text = strfmt("Decompile the function %s at %s.\n\n",
                     func_name(pfn->start_ea).c_str(), hex_str(pfn->start_ea).c_str()) + out->body;
  if ( settings().verbose )
    for ( const auto &sz : out->sizes )
      log_debug("section %-36s %6u chars", sz.first.c_str(), unsigned(sz.second));
  return true;
}

//------------------------------------------------------------------------------
// need_more
//------------------------------------------------------------------------------
static std::string requested_function(ea_t ea, std::string *why)
{
  func_t *f = get_func(ea);
  if ( f == nullptr )
  {
    *why = "not a function";
    return std::string();
  }
  size_t n = count_insns(f);
  if ( n > MAX_REQUESTED_INSNS )
  {
    *why = strfmt("too large (%u instructions)", unsigned(n));
    return std::string();
  }
  type_set_t types;
  cfg_t cfg(f);
  std::string out = "-- function " + func_name(f->start_ea) + " (" + hex_str(f->start_ea) + ")\n";
  out += header_section(f, n, cfg.order.size(), &types).render();
  out += frame_section(f, &types).render();
  out += "Listing:\n" + function_listing(f, &types);
  return out;
}

static std::string requested_data(ea_t ea, std::string *why)
{
  type_set_t types;
  std::string d = describe_data(ea, &types);
  if ( d.empty() )
  {
    *why = "not a data item";
    return std::string();
  }
  std::string out = "-- data " + d + "\n";
  // the uses of the item
  ea_t head = get_item_head(ea);
  size_t n = 0;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(head, XREF_DATA); ok && n < MAX_DATA_XREFS; ok = xb.next_to(), n++ )
  {
    func_t *f = get_func(xb.from);
    out += "  used " + std::string(f != nullptr ? "in " + func_name(f->start_ea) + " " : "")
         + "at " + hex_str(xb.from) + ": " + disasm_line(xb.from) + "\n";
  }
  for ( const auto &name : types.names )
  {
    std::string def = type_definition(name);
    if ( !def.empty() )
      out += def + "\n";
  }
  return out;
}

static std::string requested_struct(const std::string &target, std::string *why)
{
  std::string name = target;
  // an address: the type of the item there
  ea_t ea = parse_address(target);
  if ( ea != BADADDR && get_named_type(get_idati(), target.c_str(), NTF_TYPE) == 0 )
  {
    tinfo_t tif;
    type_set_t ts;
    if ( get_tinfo(&tif, get_item_head(ea)) )
      ts.add(tif);
    if ( ts.names.empty() )
    {
      *why = "no structure type at that address";
      return std::string();
    }
    name = ts.names[0];
  }
  // "struct foo" / "foo *" -> foo
  for ( const char *kw : { "struct ", "union ", "enum ", "const " } )
    if ( name.compare(0, strlen(kw), kw) == 0 )
      name = name.substr(strlen(kw));
  while ( !name.empty() && (name.back() == '*' || name.back() == ' ') )
    name.pop_back();
  std::string def = type_definition(name);
  if ( def.empty() )
  {
    *why = "unknown type";
    return std::string();
  }
  return "-- type " + name + "\n" + def + "\n";
}

std::string collect_requested(
        const std::vector<need_more_t> &reqs,
        std::set<std::string> *seen,
        size_t budget,
        std::vector<std::string> *ignored)
{
  std::string out;
  size_t served = 0;
  for ( const auto &r : reqs )
  {
    std::string what = r.what;
    std::string why;
    std::string text;
    std::string key;
    if ( served >= MAX_REQUESTS )
    {
      why = "too many requests in one round";
    }
    else if ( what == "struct" )
    {
      key = "struct:" + r.target;
      if ( seen->count(key) != 0 )
        why = "already given";
      else
        text = requested_struct(r.target, &why);
    }
    else if ( what == "function" || what == "data" )
    {
      ea_t ea = parse_address(r.target);
      if ( ea == BADADDR )
      {
        why = "not an address or a name of the database";
      }
      else
      {
        if ( what == "function" && get_func(ea) != nullptr )
          ea = get_func(ea)->start_ea;
        key = what + ":" + hex_str(ea);
        if ( seen->count(key) != 0 )
          why = "already given";
        else
          text = what == "function" ? requested_function(ea, &why) : requested_data(ea, &why);
      }
    }
    else
    {
      why = "unknown kind '" + what + "'";
    }
    if ( text.empty() || out.size() + text.size() > budget )
    {
      if ( !text.empty() )
        why = "too large for the size budget";
      ignored->push_back(what + " " + r.target + ": " + why);
      continue;
    }
    seen->insert(key);
    out += text + "\n";
    served++;
  }
  return out;
}

} // namespace clauderays
