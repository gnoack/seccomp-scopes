#include <linux/filter.h>  /* struct sock_fprog */

void append_open_filter(unsigned int scopes, struct sock_fprog* prog);
void append_rpath_filter(unsigned int scopes, struct sock_fprog* prog);
void append_dpath_filter(unsigned int scopes, struct sock_fprog* prog);
void append_cpath_filter(unsigned int scopes, struct sock_fprog* prog);
