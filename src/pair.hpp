// Claude-Rays Decompiler - diff of two versions of a function in one query
// The body of the C API used by Diaphora-ng (api.cpp): version A is a function
// of the open database, version B comes from the other database (its exported
// SQLite) inside the request. One query decompiles both, aligned, and lists
// and assesses the changes. Request and response are JSON; the format is in
// the README (C API).
#pragma once

#include "common.hpp"

namespace clauderays
{

// main thread: run the query (or take it from the cache) with the wait box,
// and return the response; it never fails without a response ("ok": false
// and "error" then)
std::string diff_functions(const std::string &request_json);

} // namespace clauderays
