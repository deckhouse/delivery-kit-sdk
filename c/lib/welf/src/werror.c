#include <stdio.h>
#include <stdarg.h>

static char welf_last_errmsg[256];

void welf_set_errmsg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(welf_last_errmsg, sizeof(welf_last_errmsg), fmt, args);
    va_end(args);
}

const char *welf_errmsg(void) {
    return welf_last_errmsg;
}
