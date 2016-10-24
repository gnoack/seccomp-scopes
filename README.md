# seccomp-scopes

Goal: Make application level sandboxing easy
and mitigate the consequences of an attacker taking control of a process.

  **BETA SOFTWARE**: Do not use for production quality software yet,
  but give it a go and let me know if you run into issues.

## TL;DR

Current implementation is like OpenBSD's `pledge()` (but only supports
a subset of the features):

    // Open a bunch of files.
    if (pledge("stdio", NONE) == -1) {
        errx(1, "Could not pledge!");
    }
    // From now on only basic input and output on previously
    // opened file descriptors are allowed, as well as acquiring
    // anonymous virtual memory.

Any attempt to do system calls outside the previously "pledged"
functionality will not be permitted and signal `SIGSYS` to the
process.

## Motivation

Unsafe languages like C have a long history of memory corruption bugs,
which can be exploited by attackers through specially crafted input
data, giving them full control over the program.

Ideally, the world would abandon most software written in C, but

* rewriting software is expensive
* some software is purposefully written in C, such as system software
  and very performance-critical libraries

Moreover, there are entire software categories such as multimedia
libraries, which are both regularly written in C, and which at the
same time regularly handle data from untrusted sources.

This project wants to make it easy for Linux processes to lock
themselves into a very narrow set of privileged operations (system
calls), providing enough privileges for the task at hand, but
restricting potential attackers who take over the process.

The project builds on Linux's `seccomp(2)` feature, which provides
great value, but is also difficult to configure and use, requiring
detailed understanding of Linux's system calls.  Seccomp-scopes
abstracts away these complexities with a simpler interface and more
coarse-grained "permission scopes".  The scopes provide sensible
presets for common tasks and let application developers talk about
operating system features in a more abstract way than by listing
system call numbers.

Seccomp-scopes is strongly inspired by OpenBSD's `pledge()` feature.

## In simple words

> The system call is the fundamental interface between an application
> and the Linux kernel.  -- syscalls(2)

On their own, Linux processes only have access to their own (virtual)
memory, but not to system resources such as hardware, which is shared
between processes and whose usage is coordinated by the operating
system.

In order to do privileged operations such as reading data from disk,
processes invoke a so-called *system call* to ask the operating system
for help.  The operating system does necessary permission checks and
then performs the requested operation on behalf of the process.

For example, in order to open a file for reading, a process might
invoke the `open()` system call, which returns a handle ("file
descriptor") to the opened file:

    int fd = open("hello.txt", O_RDONLY);

With the `seccomp(2)` Linux kernel feature, processes can drop their
ability to do system calls of their own choosing.  This ability can
not be regained for that process, and the same restrictions also apply
to any attacker who manages to take over the process.

## Example: Multimedia processing

Multimedia libraries for parsing multimedia file formats

* are often written in C for performance reasons,
* regularly process untrusted data, and
* are usually large enough to contain an unknown number of bugs.

However, after opening the required files for reading, and having a
file descriptor for writing the results, a multimedia parser usually
doesn't need many additional permissions.  In fact, the only system
calls still needed are now for:

* allocating more memory (system calls that `malloc()` calls internally)
* reading and writing on open file descriptors
* exiting the process

The core of the multimedia processing is otherwise just making use of
the CPU for processing and of the existing process virtual memory,
which are both available without system calls.

Note that the time at which the parser is dropping permissions is
before it started looking at any attacker-provided data.  If an
attacker gains control over the process through the multimedia data,
he will be trapped in a sandboxed process where the only malevolence
possible is to write a different result out over the output file
descriptor.

The attacker
* *can not* see or manipulate any files on the system
* *can not* access the network
* *can not* see or manipulate processes in the system
* *can not* make use of other resources the process user has access to
* etc.
