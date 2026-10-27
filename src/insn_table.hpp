// Claude-Rays Decompiler - mnemonic tables (x86/x64)
// Pure functions over mnemonics and values, free of IDA headers so they can
// be tested on their own.
#pragma once

#include <cstdint>
#include <string>

namespace clauderays
{

// how a flag-setting instruction compared its operands
enum flag_setter_t
{
  FS_UNKNOWN,       // arithmetic / logic, or no setter found in the block
  FS_CMP,           // cmp a, b
  FS_TEST_SAME,     // test a, a
  FS_TEST,          // test a, b
  FS_FLOAT,         // comiss / ucomisd / fcomi ...: CF/ZF/PF from a float compare
};

// the kind of flag setter 'mnem' is; 'same_operands' for test a, a
flag_setter_t classify_flag_setter(const std::string &mnem, bool same_operands);

// does 'mnem' leave the flags alone (mov, lea, push, pop, ...)?
bool keeps_flags(const std::string &mnem);

// condition code of a jcc / setcc / cmovcc mnemonic ("l" for jl, "nbe" for
// cmovnbe), "" if 'mnem' is not a conditional instruction
std::string condition_code(const std::string &mnem);

// the relation tested by a condition code after a given flag setter, e.g.
// "signed <", "unsigned >=", "==", "float <", "signed <= 0", "(a & b) == 0".
// "" if the condition code is unknown
std::string cc_relation(const std::string &cc, flag_setter_t setter);

// facts of the mnemonic itself ("sign-extend", "unsigned divide", ...), ""
// if none. 'nops' is the number of explicit operands, 'rep' a rep prefix
std::string mnemonic_fact(const std::string &mnem, int nops, bool rep);

// extension done by a load: 1 = sign (movsx, movsxd), 2 = zero (movzx), 0
int extension_kind(const std::string &mnem);

// "u8", "i16", "32-bit", "f64", "128-bit"... 'ext' as returned by
// extension_kind(), 'is_float' for floating point data types
std::string size_name(size_t bytes, int ext, bool is_float);

// a printable ASCII rendering of a constant: "'/'" for 0x2F, "\"MZ\"" for
// 0x5A4D (bytes in memory order); "" if the value is not printable text
std::string ascii_constant(uint64_t value, size_t nbytes);

} // namespace clauderays
