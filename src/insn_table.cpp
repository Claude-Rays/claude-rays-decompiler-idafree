// Claude-Rays Decompiler - mnemonic tables (x86/x64)
#include "insn_table.hpp"

#include <cctype>
#include <cstring>

namespace clauderays
{

static bool starts_with(const std::string &s, const char *prefix)
{
  return s.compare(0, strlen(prefix), prefix) == 0;
}

static bool one_of(const std::string &s, std::initializer_list<const char *> list)
{
  for ( const char *x : list )
    if ( s == x )
      return true;
  return false;
}

//------------------------------------------------------------------------------
flag_setter_t classify_flag_setter(const std::string &mnem, bool same_operands)
{
  if ( mnem == "cmp" )
    return FS_CMP;
  if ( mnem == "test" )
    return same_operands ? FS_TEST_SAME : FS_TEST;
  if ( one_of(mnem, { "comiss", "comisd", "ucomiss", "ucomisd",
                      "vcomiss", "vcomisd", "vucomiss", "vucomisd",
                      "fcomi", "fcomip", "fucomi", "fucomip" }) )
  {
    return FS_FLOAT;
  }
  return FS_UNKNOWN;
}

bool keeps_flags(const std::string &mnem)
{
  if ( one_of(mnem, { "mov", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop",
                      "xchg", "bswap", "not", "cdq", "cdqe", "cqo", "cwde", "cbw", "cwd",
                      "movd", "movq", "movss", "movsd", "movaps", "movups", "movdqa", "movdqu",
                      "endbr64", "endbr32" }) )
  {
    return true;
  }
  // cmovcc / setcc read the flags but do not change them
  return starts_with(mnem, "cmov") || (starts_with(mnem, "set") && mnem != "setssbsy");
}

//------------------------------------------------------------------------------
static bool is_cc(const std::string &cc)
{
  return one_of(cc, { "o", "no", "b", "c", "nae", "ae", "nb", "nc", "e", "z", "ne", "nz",
                      "be", "na", "a", "nbe", "s", "ns", "p", "pe", "np", "po",
                      "l", "nge", "ge", "nl", "le", "ng", "g", "nle" });
}

std::string condition_code(const std::string &mnem)
{
  std::string cc;
  if ( starts_with(mnem, "cmov") )
    cc = mnem.substr(4);
  else if ( starts_with(mnem, "set") )
    cc = mnem.substr(3);
  else if ( starts_with(mnem, "j") && mnem != "jmp" )
    cc = mnem.substr(1);
  else
    return std::string();
  return is_cc(cc) ? cc : std::string();
}

//------------------------------------------------------------------------------
// canonical name of a condition code
static std::string canon_cc(const std::string &cc)
{
  if ( one_of(cc, { "c", "nae" }) ) return "b";
  if ( one_of(cc, { "nb", "nc" }) )  return "ae";
  if ( cc == "z" )                   return "e";
  if ( cc == "nz" )                  return "ne";
  if ( cc == "na" )                  return "be";
  if ( cc == "nbe" )                 return "a";
  if ( cc == "pe" )                  return "p";
  if ( cc == "po" )                  return "np";
  if ( cc == "nge" )                 return "l";
  if ( cc == "nl" )                  return "ge";
  if ( cc == "ng" )                  return "le";
  if ( cc == "nle" )                 return "g";
  return cc;
}

std::string cc_relation(const std::string &raw_cc, flag_setter_t setter)
{
  if ( !is_cc(raw_cc) )
    return std::string();
  std::string cc = canon_cc(raw_cc);
  if ( setter == FS_FLOAT )
  {
    // ZF/PF/CF as set by comiss & co. (unordered sets all three)
    if ( cc == "b" )  return "float < (or unordered)";
    if ( cc == "ae" ) return "float >=";
    if ( cc == "be" ) return "float <= (or unordered)";
    if ( cc == "a" )  return "float >";
    if ( cc == "e" )  return "float == (or unordered)";
    if ( cc == "ne" ) return "float != (and ordered)";
    if ( cc == "p" )  return "float unordered (NaN)";
    if ( cc == "np" ) return "float ordered (no NaN)";
  }
  if ( setter == FS_TEST_SAME )
  {
    // test x, x: CF = OF = 0, the relations are against 0
    if ( cc == "e" )  return "== 0";
    if ( cc == "ne" ) return "!= 0";
    if ( cc == "l" || cc == "s" )   return "signed < 0";
    if ( cc == "ge" || cc == "ns" ) return "signed >= 0";
    if ( cc == "le" ) return "signed <= 0";
    if ( cc == "g" )  return "signed > 0";
    if ( cc == "a" )  return "!= 0";
    if ( cc == "be" ) return "== 0";
    if ( cc == "b" )  return "never (CF = 0 after test)";
    if ( cc == "ae" ) return "always (CF = 0 after test)";
  }
  if ( setter == FS_TEST )
  {
    if ( cc == "e" )  return "(a & b) == 0";
    if ( cc == "ne" ) return "(a & b) != 0";
    if ( cc == "s" || cc == "l" )   return "(a & b) sign bit set";
    if ( cc == "ns" || cc == "ge" ) return "(a & b) sign bit clear";
  }
  if ( cc == "b" )  return "unsigned <";
  if ( cc == "ae" ) return "unsigned >=";
  if ( cc == "be" ) return "unsigned <=";
  if ( cc == "a" )  return "unsigned >";
  if ( cc == "l" )  return "signed <";
  if ( cc == "ge" ) return "signed >=";
  if ( cc == "le" ) return "signed <=";
  if ( cc == "g" )  return "signed >";
  if ( cc == "e" )  return "==";
  if ( cc == "ne" ) return "!=";
  if ( cc == "s" )  return "result < 0 (sign set)";
  if ( cc == "ns" ) return "result >= 0 (sign clear)";
  if ( cc == "o" )  return "signed overflow";
  if ( cc == "no" ) return "no signed overflow";
  if ( cc == "p" )  return "parity even";
  if ( cc == "np" ) return "parity odd";
  return std::string();
}

//------------------------------------------------------------------------------
std::string mnemonic_fact(const std::string &mnem, int nops, bool rep)
{
  if ( mnem == "idiv" ) return "signed divide";
  if ( mnem == "div" )  return "unsigned divide";
  if ( mnem == "imul" && nops == 1 ) return "signed widening multiply";
  if ( mnem == "mul" )  return "unsigned widening multiply";
  if ( mnem == "sar" )  return "arithmetic shift right (signed)";
  if ( mnem == "shr" )  return "logical shift right (unsigned)";
  if ( mnem == "cdq" )  return "sign-extend eax into edx:eax";
  if ( mnem == "cqo" )  return "sign-extend rax into rdx:rax";
  if ( mnem == "cwd" )  return "sign-extend ax into dx:ax";
  if ( mnem == "cdqe" ) return "sign-extend eax to rax";
  if ( mnem == "cwde" ) return "sign-extend ax to eax";
  if ( mnem == "cbw" )  return "sign-extend al to ax";
  if ( one_of(mnem, { "cvttss2si", "cvttsd2si" }) ) return "float to int, truncating";
  if ( one_of(mnem, { "cvtsi2ss", "cvtsi2sd" }) )   return "signed int to float";
  if ( starts_with(mnem, "stos") )
    return rep ? "memset idiom: rcx/ecx elements of al/ax/eax/rax to [rdi]" : std::string();
  if ( starts_with(mnem, "movs") && mnem.size() == 5 && strchr("bwdq", mnem[4]) != nullptr )
    return rep ? "memcpy idiom: rcx/ecx elements from [rsi] to [rdi]" : std::string();
  if ( starts_with(mnem, "scas") )
    return rep ? "repne scas: strlen / memchr idiom" : std::string();
  if ( starts_with(mnem, "cmps") && mnem.size() == 5 )
    return rep ? "repe cmps: memcmp idiom" : std::string();
  return std::string();
}

int extension_kind(const std::string &mnem)
{
  if ( mnem == "movsx" || mnem == "movsxd" )
    return 1;
  if ( mnem == "movzx" )
    return 2;
  return 0;
}

std::string size_name(size_t bytes, int ext, bool is_float)
{
  if ( is_float && (bytes == 4 || bytes == 8 || bytes == 10) )
    return "f" + std::to_string(bytes * 8);
  if ( ext == 1 )
    return "i" + std::to_string(bytes * 8);
  if ( ext == 2 )
    return "u" + std::to_string(bytes * 8);
  if ( bytes == 0 )
    return "?-bit";
  return std::to_string(bytes * 8) + "-bit";
}

std::string ascii_constant(uint64_t value, size_t nbytes)
{
  if ( nbytes == 0 || nbytes > 8 )
    nbytes = 8;
  // significant bytes in memory (little endian) order
  std::string text;
  uint64_t v = value;
  size_t n = 0;
  for ( size_t i = 0; i < nbytes && v != 0; i++, v >>= 8 )
    n = i + 1;
  if ( n == 0 )
    return std::string();
  for ( size_t i = 0; i < n; i++ )
  {
    unsigned char c = (unsigned char)((value >> (i * 8)) & 0xFF);
    if ( c < 0x20 || c > 0x7E )
      return std::string();
    text += char(c);
  }
  if ( n == 1 )
  {
    if ( text == "'" )
      return "'\\''";
    if ( text == "\\" )
      return "'\\\\'";
    return "'" + text + "'";
  }
  // "ab" style multi character constants need two or more letters to be
  // worth it (avoids annotating sizes like 0x2020)
  size_t alpha = 0;
  for ( char c : text )
    alpha += isalpha((unsigned char)c) != 0;
  if ( alpha < 2 )
    return std::string();
  return "\"" + text + "\" in memory";
}

} // namespace clauderays
