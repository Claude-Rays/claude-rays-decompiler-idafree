// Claude-Rays Decompiler - child process launcher (CreateProcessW + job object)
#include "process.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <thread>

namespace clauderays
{

//------------------------------------------------------------------------------
static std::wstring utf8_to_wide(const std::string &s)
{
  if ( s.empty() )
    return std::wstring();
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
  std::wstring w(size_t(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), &w[0], n);
  return w;
}

static std::string wide_to_utf8(const std::wstring &w)
{
  if ( w.empty() )
    return std::string();
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(size_t(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), &s[0], n, nullptr, nullptr);
  return s;
}

//------------------------------------------------------------------------------
static std::string last_error_text(const char *what)
{
  DWORD code = GetLastError();
  char buf[256];
  const char *desc = nullptr;
  switch ( code )
  {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:   desc = "file not found"; break;
    case ERROR_ACCESS_DENIED:    desc = "access denied"; break;
    case ERROR_BAD_EXE_FORMAT:   desc = "not a valid executable (point it to claude.exe)"; break;
  }
  if ( desc != nullptr )
    snprintf(buf, sizeof(buf), "%s failed: %s (error %lu)", what, desc, code);
  else
    snprintf(buf, sizeof(buf), "%s failed (error %lu)", what, code);
  return buf;
}

//------------------------------------------------------------------------------
// one argument quoted the way CommandLineToArgvW / the MS C runtime parse it
static void append_quoted(std::wstring *cmd, const std::wstring &arg)
{
  if ( !cmd->empty() )
    *cmd += L' ';
  if ( !arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos )
  {
    *cmd += arg;
    return;
  }
  *cmd += L'"';
  for ( size_t i = 0; ; i++ )
  {
    size_t nbs = 0;
    while ( i < arg.size() && arg[i] == L'\\' )
    {
      i++;
      nbs++;
    }
    if ( i == arg.size() )
    {
      // double the trailing backslashes: the closing quote follows
      cmd->append(nbs * 2, L'\\');
      break;
    }
    if ( arg[i] == L'"' )
    {
      cmd->append(nbs * 2 + 1, L'\\');
      *cmd += L'"';
    }
    else
    {
      cmd->append(nbs, L'\\');
      *cmd += arg[i];
    }
  }
  *cmd += L'"';
}

//------------------------------------------------------------------------------
static void read_all(HANDLE h, std::string *out)
{
  char buf[16 * 1024];
  for ( ;; )
  {
    DWORD got = 0;
    if ( !ReadFile(h, buf, DWORD(sizeof(buf)), &got, nullptr) || got == 0 )
      break;
    out->append(buf, got);
  }
}

static void write_all(HANDLE h, const std::string &data)
{
  size_t off = 0;
  while ( off < data.size() )
  {
    DWORD chunk = DWORD(std::min<size_t>(data.size() - off, 64 * 1024));
    DWORD put = 0;
    if ( !WriteFile(h, data.data() + off, chunk, &put, nullptr) )
      break;      // the child closed its stdin or was killed
    off += put;
  }
}

//------------------------------------------------------------------------------
// an anonymous pipe whose 'child' end is inheritable and the other one is not
static bool make_pipe(HANDLE *parent, HANDLE *child, bool child_reads)
{
  SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
  HANDLE r = nullptr;
  HANDLE w = nullptr;
  if ( !CreatePipe(&r, &w, &sa, 0) )
    return false;
  *parent = child_reads ? w : r;
  *child = child_reads ? r : w;
  SetHandleInformation(*parent, HANDLE_FLAG_INHERIT, 0);
  return true;
}

static void close_handle(HANDLE *h)
{
  if ( *h != nullptr && *h != INVALID_HANDLE_VALUE )
    CloseHandle(*h);
  *h = nullptr;
}

//------------------------------------------------------------------------------
process_run_t::~process_run_t()
{
  std::lock_guard<std::mutex> lock(mtx);
  if ( hjob != nullptr )
    CloseHandle(HANDLE(hjob));    // KILL_ON_JOB_CLOSE
  hjob = nullptr;
}

//------------------------------------------------------------------------------
void process_run_t::cancel()
{
  std::lock_guard<std::mutex> lock(mtx);
  cancelled = true;
  if ( hjob != nullptr )
    TerminateJobObject(HANDLE(hjob), 1);
}

//------------------------------------------------------------------------------
bool process_run_t::run(
        const std::string &exe,
        const std::vector<std::string> &args,
        const std::string &cwd,
        const std::string &stdin_data,
        int timeout_s,
        std::string *out,
        std::string *errout,
        int *exit_code,
        std::string *err)
{
  out->clear();
  errout->clear();
  *exit_code = -1;

  std::wstring wexe = utf8_to_wide(exe);
  std::wstring cmdline;
  append_quoted(&cmdline, wexe);
  for ( const auto &a : args )
    append_quoted(&cmdline, utf8_to_wide(a));
  if ( cmdline.size() >= 32767 )
  {
    *err = "the command line is too long";
    return false;
  }
  std::wstring wcwd = utf8_to_wide(cwd);

  HANDLE in_parent = nullptr, in_child = nullptr;
  HANDLE out_parent = nullptr, out_child = nullptr;
  HANDLE err_parent = nullptr, err_child = nullptr;
  if ( !make_pipe(&in_parent, &in_child, true)
    || !make_pipe(&out_parent, &out_child, false)
    || !make_pipe(&err_parent, &err_child, false) )
  {
    *err = last_error_text("CreatePipe");
    close_handle(&in_parent); close_handle(&in_child);
    close_handle(&out_parent); close_handle(&out_child);
    close_handle(&err_parent); close_handle(&err_child);
    return false;
  }

  // Inherit only our three pipe ends: with several queries running at once a
  // child must not keep another child's stdout open (its reader would never
  // see the end of the pipe).
  HANDLE inherit[3] = { in_child, out_child, err_child };
  SIZE_T attr_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
  std::vector<char> attr_buf(attr_size);
  auto *attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
  bool attrs_ok = InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)
               && UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                            inherit, sizeof(inherit), nullptr, nullptr);

  STARTUPINFOEXW si = {};
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = in_child;
  si.StartupInfo.hStdOutput = out_child;
  si.StartupInfo.hStdError = err_child;
  si.lpAttributeList = attrs_ok ? attrs : nullptr;

  PROCESS_INFORMATION pi = {};
  bool started = false;
  {
    std::lock_guard<std::mutex> lock(mtx);
    if ( cancelled )
    {
      *err = "cancelled";
    }
    else
    {
      hjob = CreateJobObjectW(nullptr, nullptr);
      if ( hjob != nullptr )
      {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = {};
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(HANDLE(hjob), JobObjectExtendedLimitInformation, &li, sizeof(li));
      }
      DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
                  | (attrs_ok ? EXTENDED_STARTUPINFO_PRESENT : 0);
      started = CreateProcessW(wexe.c_str(), &cmdline[0], nullptr, nullptr, TRUE, flags,
                               nullptr, wcwd.empty() ? nullptr : wcwd.c_str(),
                               &si.StartupInfo, &pi) != FALSE;
      if ( !started )
      {
        *err = last_error_text(("starting '" + exe + "'").c_str());
      }
      else
      {
        // assign before the first instruction runs, so its children are in too
        if ( hjob != nullptr )
          AssignProcessToJobObject(HANDLE(hjob), pi.hProcess);
        ResumeThread(pi.hThread);
      }
    }
  }
  if ( attrs_ok )
    DeleteProcThreadAttributeList(attrs);
  // the child has its own copies now: keeping ours would prevent EOF
  close_handle(&in_child);
  close_handle(&out_child);
  close_handle(&err_child);
  if ( !started )
  {
    close_handle(&in_parent);
    close_handle(&out_parent);
    close_handle(&err_parent);
    return false;
  }
  close_handle(&pi.hThread);

  // stdin, stdout and stderr in parallel so a full pipe never blocks the child
  std::thread writer([&]() { write_all(in_parent, stdin_data); close_handle(&in_parent); });
  std::thread rd_out([&]() { read_all(out_parent, out); });
  std::thread rd_err([&]() { read_all(err_parent, errout); });

  DWORD wait = WaitForSingleObject(pi.hProcess, timeout_s > 0 ? DWORD(timeout_s) * 1000 : INFINITE);
  bool ok = true;
  if ( wait != WAIT_OBJECT_0 )
  {
    *err = wait == WAIT_TIMEOUT
         ? "timed out after " + std::to_string(timeout_s) + " s"
         : last_error_text("waiting for the process");
    ok = false;
  }
  {
    // kill the process if it is still running and whatever it left behind:
    // the pipes only reach EOF once every holder is gone
    std::lock_guard<std::mutex> lock(mtx);
    if ( hjob != nullptr )
      TerminateJobObject(HANDLE(hjob), 1);
    else if ( !ok )
      TerminateProcess(pi.hProcess, 1);
  }
  writer.join();
  rd_out.join();
  rd_err.join();
  close_handle(&out_parent);
  close_handle(&err_parent);

  DWORD code = 0;
  if ( GetExitCodeProcess(pi.hProcess, &code) )
    *exit_code = int(code);
  close_handle(&pi.hProcess);

  std::lock_guard<std::mutex> lock(mtx);
  if ( hjob != nullptr )
    CloseHandle(HANDLE(hjob));
  hjob = nullptr;
  if ( cancelled )
  {
    *err = "cancelled";
    ok = false;
  }
  return ok;
}

//------------------------------------------------------------------------------
static bool is_file(const std::wstring &p)
{
  DWORD a = GetFileAttributesW(p.c_str());
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::wstring expand_env(const std::wstring &s)
{
  DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
  if ( n == 0 )
    return s;
  std::wstring out(n, L'\0');
  n = ExpandEnvironmentStringsW(s.c_str(), &out[0], n);
  if ( n == 0 )
    return s;
  out.resize(n - 1);
  return out;
}

std::string find_executable(const std::string &name)
{
  std::wstring w = expand_env(utf8_to_wide(name));
  if ( w.empty() )
    return std::string();
  bool has_ext = w.size() > 4 && _wcsicmp(w.c_str() + w.size() - 4, L".exe") == 0;
  if ( w.find_first_of(L"\\/:") != std::wstring::npos )
  {
    if ( is_file(w) )
      return wide_to_utf8(w);
    if ( !has_ext && is_file(w + L".exe") )
      return wide_to_utf8(w + L".exe");
    return std::string();
  }

  wchar_t buf[MAX_PATH * 2];
  DWORD n = SearchPathW(nullptr, w.c_str(), L".exe", DWORD(_countof(buf)), buf, nullptr);
  if ( n > 0 && n < _countof(buf) )
    return wide_to_utf8(buf);

  // IDA may have been started before the installer added this folder to PATH
  std::wstring local = expand_env(L"%USERPROFILE%\\.local\\bin\\") + w + (has_ext ? L"" : L".exe");
  if ( is_file(local) )
    return wide_to_utf8(local);
  return std::string();
}

//------------------------------------------------------------------------------
std::string neutral_work_dir()
{
  wchar_t tmp[MAX_PATH + 1];
  DWORD n = GetTempPathW(DWORD(_countof(tmp)), tmp);
  if ( n == 0 || n > MAX_PATH )
    return std::string();
  std::wstring dir = std::wstring(tmp) + L"clauderays";
  if ( !CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS )
    return std::string();
  return wide_to_utf8(dir);
}

//------------------------------------------------------------------------------
bool set_clipboard_text(const std::string &utf8)
{
  std::wstring w = utf8_to_wide(utf8);
  // the clipboard wants CRLF line ends
  std::wstring text;
  for ( wchar_t c : w )
  {
    if ( c == L'\n' )
      text += L'\r';
    text += c;
  }
  if ( !OpenClipboard(nullptr) )
    return false;
  bool ok = false;
  EmptyClipboard();
  size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if ( h != nullptr )
  {
    void *p = GlobalLock(h);
    if ( p != nullptr )
    {
      memcpy(p, text.c_str(), bytes);
      GlobalUnlock(h);
      ok = SetClipboardData(CF_UNICODETEXT, h) != nullptr;
    }
    if ( !ok )
      GlobalFree(h);
  }
  CloseClipboard();
  return ok;
}

} // namespace clauderays
