#ifndef WERROR_H
#define WERROR_H

void welf_set_errmsg(const char *fmt, ...);

const char *welf_errmsg(void);

#endif
