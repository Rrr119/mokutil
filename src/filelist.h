#ifndef __MOKUTIL_FILELIST_H__
#define __MOKUTIL_FILELIST_H__

#include <stddef.h>

int mok_file_list_load(const char *manifest, char ***files, size_t *count,
		       char **error);
void mok_file_list_free(char **files, size_t count);

#endif /* __MOKUTIL_FILELIST_H__ */
