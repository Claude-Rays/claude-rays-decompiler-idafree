// Claude-Rays Decompiler - C API for other plugins (Diaphora-ng)
// Found at run time with GetProcAddress: no link time dependency. Request and
// response are UTF-8 JSON, so no C++ structure crosses the DLL boundary; new
// optional fields keep the version.
#include "pair.hpp"

#include <stdlib.h>
#include <string.h>

#define CLAUDERAYS_API_VERSION 1

extern "C" __declspec(dllexport) int clauderays_api_version(void)
{
  return CLAUDERAYS_API_VERSION;
}

// Main thread only. Shows the wait box (with Cancel) while Claude works.
// The result is always a JSON object; release it with clauderays_free().
extern "C" __declspec(dllexport) char *clauderays_diff_functions(const char *request_json)
{
  std::string out = clauderays::diff_functions(request_json != nullptr ? request_json : "");
  char *p = (char *)malloc(out.size() + 1);
  if ( p != nullptr )
    memcpy(p, out.c_str(), out.size() + 1);
  return p;
}

extern "C" __declspec(dllexport) void clauderays_free(char *p)
{
  free(p);
}
