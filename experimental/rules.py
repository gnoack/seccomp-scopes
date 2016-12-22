import collections

from ast import *
from compile import SmartEmit, CPrintingEmit


def IfSyscall(name, then):
  return If(Eq(SysNr(), Value("__NR_" + name)),
            then)

def IfScope(name, then):
  return If(HasScope(name),
            then)


def Allow():
  return Return(Value("SECCOMP_RET_ALLOW"))


def Deny():
  return Return(Value("SECCOMP_RET_DENY"))


Rule = HasScope


def InvertSyscallMap(syscalls):
  # Return syscall names by matcher.
  result = collections.defaultdict(list)
  for k, v in syscalls.items():
    result[v].append(k)
  return result


def IterDict(syscalls):
  # iterate in canonical order
  result = []
  for matcher, syscalls in syscalls.items():
    result.append((matcher, sorted(syscalls)))
  return sorted(result, key=lambda x: x[1])


def SyscallsToRule(syscalls):
  # syscalls is a dict from syscall names to matchers.
  syscalls_by_matcher = InvertSyscallMap(syscalls)
  stmts = []
  for matcher, syscalls in IterDict(syscalls_by_matcher):
    stmts.append(If(Or(*map(lambda n: Eq(SysNr(), Value("__NR_" + n)),
                            syscalls)),
                    If(matcher,
                       Allow(),
                       Deny())))
  stmts.append(Deny())  # default fallback
  return Do(*stmts)


def Establish():
  stdio = HasScope("stdio")
  rpath = HasScope("rpath")
  cpath = HasScope("cpath")
  dpath = HasScope("dpath")
  inet = HasScope("inet")
  memory = HasScope("memory")

  C = Value

  syscalls = dict(
    read=stdio,
    readv=stdio,
    pread64=stdio,
    preadv=stdio,
    preadv2=stdio,

    write=stdio,
    writev=stdio,
    pwrite64=stdio,
    pwritev=stdio,
    pwritev2=stdio,

    fstat=stdio,
    fstat64=stdio,
    clock_gettime=stdio,
    clock_getres=stdio,
    close=stdio,

    chdir=rpath,

    link=cpath,
    linkat=cpath,
    mkdir=cpath,
    mkdirat=cpath,
    rename=cpath,
    renameat=cpath,
    rmdir=cpath,
    symlink=cpath,
    unlink=cpath,
    unlinkat=cpath,

    mknod=dpath,
    mknotat=dpath,

    ### Networking

    socket=inet.If(Or(Eq(Arg(0), C("AF_INET")),
                      Eq(Arg(0), C("AF_INET6"))),
                   Or(Eq(Arg(1), C("SOCK_STREAM")),
                      Eq(Arg(1), C("SOCK_DGRAM")))),
    accept=inet,
    accept4=inet,
    bind=inet,
    connect=inet,
    listen=inet,
    recv=inet,
    send=inet,
    recvfrom=inet,
    sendto=inet,
    recvmsg=inet,
    sendmsg=inet,
    # TODO: sendmmsg, setsockopt, getsockopt, socketpair, getpeername

    #########################################
    ### Memory
    #########################################
    brk=memory,
    munmap=memory,
    madvise=memory,
    ## TODO: Finish
  )
  return SyscallsToRule(syscalls)


global_rule = Establish()
emit = SmartEmit(CPrintingEmit())
global_rule.compile_stmt(emit)
emit.flush()
