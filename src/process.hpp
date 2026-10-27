// Claude-Rays Decompiler - child process launcher for the Claude Code CLI
// Kept free of IDA headers so <windows.h> never meets the SDK in the same
// translation unit.
#pragma once

#include <mutex>
#include <string>
#include <vector>

namespace clauderays
{

// One synchronous run of a console program that may be aborted from another
// thread. The child gets no console window and lives in a job object, so
// cancel() - or the end of IDA - kills it together with its own children.
class process_run_t
{
public:
  process_run_t() = default;
  ~process_run_t();
  process_run_t(const process_run_t &) = delete;
  process_run_t &operator=(const process_run_t &) = delete;

  // Run 'exe' with 'args' (UTF-8, quoted for Windows here) in the directory
  // 'cwd' ("" = inherit), write 'stdin_data' to its stdin then close it, and
  // collect stdout / stderr until the process ends. timeout_s == 0 means no
  // timeout. Returns false and fills *err if the process could not be
  // started, timed out or was cancelled; otherwise *exit_code is set.
  bool run(
        const std::string &exe,
        const std::vector<std::string> &args,
        const std::string &cwd,
        const std::string &stdin_data,
        int timeout_s,
        std::string *out,
        std::string *errout,
        int *exit_code,
        std::string *err);

  // thread-safe: kill the process in flight
  void cancel();

private:
  std::mutex mtx;
  void *hjob = nullptr;
  bool cancelled = false;
};

// Resolve a program name: environment variables are expanded, a path is used
// as is (".exe" is appended if needed), a bare name is looked up in PATH and
// then in %USERPROFILE%\.local\bin (where the Claude Code installer puts it).
// Returns "" if not found.
std::string find_executable(const std::string &name);

// a neutral, empty working directory (%TEMP%\clauderays), created on demand
std::string neutral_work_dir();

// put UTF-8 text on the Windows clipboard
bool set_clipboard_text(const std::string &utf8);

} // namespace clauderays
