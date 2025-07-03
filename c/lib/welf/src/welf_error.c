#include <stdio.h>
#include <stdarg.h>

static char last_errmsg[256];

void welf_set_errmsg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_errmsg, sizeof(last_errmsg), fmt, args);
    va_end(args);
}

const char *welf_errmsg(void) {
    return last_errmsg;
}
