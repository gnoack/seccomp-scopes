
/*
 * An OpenBSD-like pledge implementation, restricting what
 * the current process may do.
 */
int pledge(const char* promises, const char* paths[]);
