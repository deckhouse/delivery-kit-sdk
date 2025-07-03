#ifndef WELF_ERROR_H
#define WELF_ERROR_H

void welf_set_errmsg(const char *fmt, ...);

const char *welf_errmsg(void);

#endif
