#include <linux/filter.h>  /* struct sock_fprog */

void append_stdio_filter(unsigned int scopes, struct sock_fprog* prog);
void append_memory_filter(unsigned int scopes, struct sock_fprog* prog);
