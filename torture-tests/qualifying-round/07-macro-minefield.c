#include <stdio.h>

#define KEYWORD int
// SQL concatenation and the static buffer are intentionally unsafe to expose macro-driven
// injection, thread safety, and overflow risks.
#define MAKE_HANDLER(name, table)                                      \
  const char *name(const char *user) {                                 \
    static char query[128];                                            \
    snprintf(query, sizeof(query), "SELECT * FROM %s WHERE user='%s'", \
             table, user);                                             \
    return query;                                                      \
  }

MAKE_HANDLER(buildQuery, "users")

#define REWRITE(x) do {                           \
    printf("rewriting %s\n", #x);                 \
  } while (0)

KEYWORD main(void) {
  REWRITE(buildQuery);
  return 0;
}
