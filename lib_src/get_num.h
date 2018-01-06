#ifndef GET_NUM
#define GET_NUM

#define BOOL            char
#define TRUE            1
#define FALSE           0

#define GN_NONNEG       01
#define GN_GT_0         02

#define GN_ANY_BASE     0100
#define GN_BASE_8       0200
#define GN_BASE_16      0400

int get_int(const char *arg, int flags, const char *name);
long get_long(const char *arg, int flags, const char *name);

#endif
