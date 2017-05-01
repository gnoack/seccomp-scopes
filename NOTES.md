# Find out called syscalls

Run the test with test name as first and pledge string as 2nd arg, such as:

    strace ./inet test_gethostbyname 'inet dns'

# ARM

Syscall number is loaded into r7 for syscall.

    (gdb) info registers
