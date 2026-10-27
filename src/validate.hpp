// Claude-Rays Decompiler - cheap validation of an answer (nothing is executed)
// Calls: every call of the function appears in the code, by name.
// Coverage: every basic block has an address annotation inside it.
// Range: no annotation points outside the function.
#pragma once

#include "common.hpp"
#include "backend.hpp"

namespace clauderays
{

// the /*0x...*/ annotations of 'code', in order
std::vector<ea_t> code_annotations(const std::string &code);

// The findings anchored to the listing: each address must fall in an
// instruction of the function (an address inside one moves to its head).
// The others are dropped, and so is a finding left without addresses, with a
// warning in *warnings: nothing is highlighted where the model only guessed.
std::vector<finding_t> anchor_findings(ea_t func_ea, const std::vector<finding_t> &findings,
                                       std::vector<std::string> *warnings);

// one readable warning per problem, empty if none
std::vector<std::string> validate_result(ea_t func_ea, const decomp_result_t &res);

// the names a call to 'callee' may have in C code (import prefixes and
// decorations removed)
std::vector<std::string> callee_name_variants(ea_t callee);

// the demangled name of 'ea' without arguments ("Ns::Cls::f<int>"), then
// without template arguments too ("Ns::Cls::f"); empty if not mangled
std::vector<std::string> demangled_names(ea_t ea);

// 'Ns::Cls<a::b>::f' -> 'Ns::Cls::f'
std::string strip_templates(const std::string &s);

// position of the "::" before the last component (npos if none), ignoring
// the ones inside template arguments
size_t last_scope(const std::string &s);

} // namespace clauderays
