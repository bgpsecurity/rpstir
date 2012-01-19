/*
  Low-level string parsing utilities
*/


int endswith(const char *s, const char *suffix);
int startswith(const char *s, const char *prefix);
void lstrip(char *s, const char *delimiters);
void rstrip(char *s, const char *delimiters);
void strip(char *s, const char *delimiters);
int exists_non_delimiter(const char *s, const char *delimiters);
char *start_of_next_field(const char *s, const char *delimiters);
char *dirname(char *dest, int dest_len, const char *path);
char *this_field(char *dest, int dest_length, const char *src,
		 const char *delimiters);
int field_length(const char *s, const char *delimiters);
int split_string(char *s, const char *delimiters,
		 char ***pfields, int *pnumfields);
int expand_by_doubling(void **ptr, size_t size, size_t *current_nmemb,
		       size_t min_nmemb);
char *scrub_for_print(char *dst, char const *src, size_t const dst_len);
