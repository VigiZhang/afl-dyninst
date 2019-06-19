#include "config.h"
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>

#define PRINT_ERROR(s) (void)(write(2, s, strlen(s))+1)

static bool forkserver_installed = false;
static s32 shm_id;
static u8 dummy[65536];
static u8 *trace_bits = dummy;
static int __afl_temp_data;
static pid_t __afl_fork_pid;
static unsigned short prev_id;
#if (__amd64__ || __x86_64__)
static long saved_di;
register long rdi asm("di");    // the warning is fine - we need the warning because of a bug in dyninst
#endif

void afl_stub_initAflForkServer() {
  if (forkserver_installed)
    return;
  forkserver_installed = true;

  char *shm_env_var = getenv(SHM_ENV_VAR);

  if (!shm_env_var) {
    PRINT_ERROR("Error getting shm\n");
    return;
  }

  shm_id = atoi(shm_env_var);
  trace_bits = (u8*) shmat(shm_id, NULL, 0);
  if (trace_bits == (u8*) -1) {
    PRINT_ERROR("Error: shmat\n");
    return;
  }

  // fork server thyme
  int n = write(FORKSRV_FD + 1, &__afl_temp_data, 4);
  if (n != 4) {
    PRINT_ERROR("Error writing fork server\n");
    return;
  }

  while (1) {
    n = read(FORKSRV_FD, &__afl_temp_data, 4);
    if (n != 4) {
      PRINT_ERROR("Error reading fork server\n");
      return;
    }

    __afl_fork_pid = fork();
    if (__afl_fork_pid < 0) {
      PRINT_ERROR("Error on fork()\n");
      return;
    }

    if (__afl_fork_pid == 0) {
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      break;
    } else {
      n = write(FORKSRV_FD + 1, &__afl_fork_pid, 4);
      pid_t temp_pid = waitpid(__afl_fork_pid, &__afl_temp_data, 0);
      if (temp_pid == 0) {
        return;
      }
      n = write(FORKSRV_FD + 1, &__afl_temp_data, 4);
    }
  }
}

void afl_stub_bbCallback(unsigned short id) {
  trace_bits[prev_id ^ id]++;
  prev_id = id >> 1;
}

void afl_stub_forceCleanExit() {
  exit(0);
}

void afl_stub_save_rdi() {
#if (__amd64__ || __x86_64__)
  saved_di = rdi;
#endif
}

void afl_stub_restore_rdi() {
#if (__amd64__ || __x86_64__)
  rdi = saved_di;
#endif
}
