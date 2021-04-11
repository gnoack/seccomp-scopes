#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>  /* open() flags */

#include <stdbool.h>  /* bool */

#include <asm/unistd.h>  /* syscall numbers */

#include "bpf_helper.h"
#include "pledge_path.h"
#include "pledge_internal.h"

// TODO: Find how to properly and libc-compatibly include the definition of O_LARGEFILE
#define O_LARGEFILE 0400000

// Opening paths read-only
void append_rpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_RPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_chdir, SECCOMP_RET_ALLOW);
  }
}


// File creation stuff
void append_cpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_CPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_link,      SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_linkat,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mkdir,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mkdirat,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rename,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_renameat,  SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_rmdir,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_symlink,   SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_unlink,    SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_unlinkat,  SECCOMP_RET_ALLOW);
    // Note: ioctl is used for fopen in musl to get tty windowsize
    // and to automatically enable buffering.
    // TODO: Move this into its own function and later support the
    // pledge 'tty' scope.
    _RET_EQ(__NR_ioctl,     SECCOMP_RET_ERRNO+EPERM);
  }
}


// Special files
void append_dpath_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & SCOPE_DPATH)) {
    return;
  }

  BPFINTO(prog) {
    _RET_EQ(__NR_mknod,     SECCOMP_RET_ALLOW);
    _RET_EQ(__NR_mknodat,   SECCOMP_RET_ALLOW);
  }
}


void append_open_filter(unsigned int scopes, struct sock_fprog* prog) {
  if (!(scopes & (SCOPE_RPATH | SCOPE_WPATH | SCOPE_CPATH))) {
    return;
  }

  bool may_read = scopes & SCOPE_RPATH;
  bool may_write = scopes & SCOPE_WPATH;
  bool may_rdwr = may_read && may_write;
  bool may_create = scopes & SCOPE_CPATH;

  // We are first checking the access mode (can be masked),
  // then the other flags in the same open() argument.
  //
  // To avoid recalculating jump targets, depending on the pledged
  // promises, some access mode comparisons are comparing to
  // O_ACCMODE+1, which is not possible. Pseudocode:
  //
  // if (nr == __NR_openat) {
  //   flags = arg2;
  // } else if (nr == __NR_open || nr == __NR_creat) {
  //   flags = arg1;
  // } else {
  //   goto exit;
  // }
  // access_mode = flags & O_ACCMODE;
  // if (access_mode == O_RDONLY ||
  //     access_mode == O_ACCMODE+1 ||  /* can't happen */
  //     access_mode == O_ACCMODE+1) {  /* can't happen */
  //   if ((flags | permitted_open_flags) == permitted_open_flags) {
  //     return SECCOMP_RET_ALLOW;
  //   }
  // }
  // exit:
  //
  // The lines marked as "can't happen" may be O_WRONLY and O_RDWR instead.
  //
  // We need to calculate the permitted_open_flags ahead of time.
  // permitted_open_flags includes O_ACCMODE, because that was checked
  // before already.
  // O_LARGEFILE is set by default on musl.
  int permitted_open_flags = O_ACCMODE;
#ifdef O_LARGEFILE
  permitted_open_flags |= O_LARGEFILE;
#endif

  if (may_write) {
    permitted_open_flags |= O_TRUNC | O_APPEND;
  }
  if (may_create) {
    permitted_open_flags |= O_CREAT | O_EXCL;
#ifdef O_TMPFILE
    permitted_open_flags |= O_TMPFILE;
#endif  // O_TMPFILE
  }

  // Construct the filter
  DECLARELABEL(checkother);
  DECLARELABEL(cleanup);
  DECLARELABEL(check_flags_argument);
  DECLARELABEL(handle_open_and_creat);
  BPFINTO(prog) {
    // For openat, take 'flags' value from arg 2.
    _JEQ(__NR_openat, 0, ELSE_TO(handle_open_and_creat));
    _LD_ARG(2);  // acc := flags (arg 2)
    _JMP(TO(check_flags_argument));

    LABEL(handle_open_and_creat);
    // For open and creat, take 'flags' value from arg 1.
    _JEQ(__NR_open, 1, 0);
    _JEQ(__NR_creat, 0, ELSE_TO(cleanup));
    _LD_ARG(1);  // acc := flags (arg 1)

    LABEL(check_flags_argument);
    _SET_X_TO_A();  // store X := flags
    // acc := flags & O_ACCMODE
    _AND(O_ACCMODE);
    // Check read/write modes
    _JEQ((may_read  ? O_RDONLY : O_ACCMODE+1), THEN_TO(checkother), 0);  // jeq rdonly checkother
    _JEQ((may_write ? O_WRONLY : O_ACCMODE+1), THEN_TO(checkother), 0);  // jeq wronly checkother
    _JEQ((may_rdwr  ? O_RDWR   : O_ACCMODE+1), THEN_TO(checkother), ELSE_TO(cleanup));  // jne rdwr   cleanup

    LABEL(checkother);  // check the other flag bits
    // if ((flags | permitted) == permitted) return SECCOMP_RET_ALLOW;
    _SET_A_TO_X();  // flags
    _OR(permitted_open_flags);
    _RET_EQ(permitted_open_flags, SECCOMP_RET_ALLOW);

    LABEL(cleanup);
    _LD_NR();
  }
}
