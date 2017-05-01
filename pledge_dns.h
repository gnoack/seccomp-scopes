
#include <linux/filter.h>  /* struct sock_fprog */

void append_dns_filter(unsigned int scopes, struct sock_fprog* prog);
