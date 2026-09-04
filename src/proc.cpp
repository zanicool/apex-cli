/// @file proc.cpp
/// @brief Safe subprocess execution without a shell (implementation).
#include "proc.hpp"

#include <array>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace apex {

namespace {

/// Convert a std::vector<std::string> to a null-terminated char* array
/// suitable for execvp. The returned pointers reference the input strings,
/// which must outlive the call.
std::vector<char *> to_argv(const std::vector<std::string> &args) {
  std::vector<char *> argv;
  argv.reserve(args.size() + 1);
  for (const auto &a : args)
    argv.push_back(const_cast<char *>(a.c_str()));
  argv.push_back(nullptr);
  return argv;
}

} // namespace

bool command_exists(const std::string &name) {
  // Resolve via `command -v` in a child, but pass the name as a literal argv
  // element — never interpolated into a shell string.
  ProcResult r = run_command({"/bin/sh", "-c", "command -v \"$0\"", name},
                             5, /*capture_stdout=*/true);
  return r.spawned && r.exit_code == 0 && !r.stdout_data.empty();
}

ProcResult run_command(const std::vector<std::string> &argv, int timeout_secs,
                       bool capture_stdout) {
  ProcResult result;
  if (argv.empty())
    return result;

  int pipefd[2] = {-1, -1};
  if (capture_stdout && pipe(pipefd) != 0)
    return result;

  pid_t pid = fork();
  if (pid < 0) {
    if (capture_stdout) {
      close(pipefd[0]);
      close(pipefd[1]);
    }
    return result;
  }

  if (pid == 0) {
    // Child.
    if (capture_stdout) {
      dup2(pipefd[1], STDOUT_FILENO);
      close(pipefd[0]);
      close(pipefd[1]);
    }
    // Silence stderr to keep tool noise out of our output.
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    if (timeout_secs > 0)
      alarm(static_cast<unsigned>(timeout_secs));

    auto cargv = to_argv(argv);
    execvp(cargv[0], cargv.data());
    _exit(127); // execvp failed.
  }

  // Parent.
  result.spawned = true;
  if (capture_stdout) {
    close(pipefd[1]);
    std::array<char, 4096> buf;
    ssize_t n;
    while ((n = read(pipefd[0], buf.data(), buf.size())) > 0)
      result.stdout_data.append(buf.data(), static_cast<size_t>(n));
    close(pipefd[0]);
  }

  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status))
    result.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status))
    result.exit_code = 128 + WTERMSIG(status);
  return result;
}

} // namespace apex
