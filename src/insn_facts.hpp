// Claude-Rays Decompiler - annotated instruction facts
// The facts the plugin computes exactly from the instruction semantics so
// the model does not have to guess them: signedness of conditional jumps,
// size and extension of memory accesses, call properties, constants.
// No UI headers here: only the processor / database API.
#pragma once

#include <pro.h>

#include <map>
#include <string>

namespace clauderays
{

// instruction facts are only computed for x86 / x64 for now
bool has_insn_facts();

// lowercase mnemonic of the instruction at 'ea'
std::string insn_mnem(ea_t ea);

// The facts of every instruction of the basic block [start, end), keyed by
// address ("unsigned <", "load u8, zero-extend", "call: noreturn", ...).
// Instructions without facts are left out.
void block_insn_facts(ea_t start, ea_t end, std::map<ea_t, std::string> *out);

// the facts of one instruction of the basic block [block_start, block_end)
std::string insn_facts_at(ea_t ea, ea_t block_start, ea_t block_end);

// the function called by the call instruction at 'ea' (through an import
// pointer too), BADADDR if indirect or unknown
ea_t call_target(ea_t ea);

} // namespace clauderays
