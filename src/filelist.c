#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "filelist.h"

#define FILELIST_ERROR_SIZE 512

static int set_error(char **error, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static int
set_error(char **error, const char *fmt, ...)
{
	va_list ap;
	char message[FILELIST_ERROR_SIZE];

	if (error) {
		va_start (ap, fmt);
		vsnprintf (message, sizeof (message), fmt, ap);
		va_end (ap);
		*error = strdup (message);
	}

	return -1;
}

static char *
trim(char *str)
{
	char *end;

	while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n')
		str++;

	end = str + strlen (str);
	while (end > str &&
	       (end[-1] == ' ' || end[-1] == '\t' ||
		end[-1] == '\r' || end[-1] == '\n'))
		end--;
	*end = '\0';

	return str;
}

static int
list_has(char *const files[], size_t count, const char *path)
{
	for (size_t i = 0; i < count; i++) {
		if (strcmp (files[i], path) == 0)
			return 1;
	}

	return 0;
}

static int
append_file(char ***files, size_t *count, const char *path, char **error)
{
	char **new_files;
	char *copy;

	if (list_has (*files, *count, path))
		return 0;

	copy = strdup (path);
	if (!copy)
		return set_error (error, "out of memory");

	new_files = realloc (*files, (*count + 1) * sizeof (**files));
	if (!new_files) {
		free (copy);
		return set_error (error, "out of memory");
	}

	new_files[*count] = copy;
	*files = new_files;
	(*count)++;

	return 0;
}

static int
append_directory(char ***files, size_t *count, const char *directory,
		 char **error)
{
	struct dirent **entries = NULL;
	int entry_count;
	int ret = 0;

	entry_count = scandir (directory, &entries, NULL, alphasort);
	if (entry_count < 0)
		return set_error (error, "cannot read directory \"%s\": %s",
				  directory, strerror (errno));

	for (int i = 0; i < entry_count; i++) {
		char *path;
		struct stat status;
		size_t path_size;

		if (entries[i]->d_name[0] == '.' &&
		    (entries[i]->d_name[1] == '\0' ||
		     (entries[i]->d_name[1] == '.' &&
		      entries[i]->d_name[2] == '\0')))
			continue;

		path_size = strlen (directory) + strlen (entries[i]->d_name) + 2;
		path = malloc (path_size);
		if (!path) {
			ret = set_error (error, "out of memory");
			break;
		}
		snprintf (path, path_size, "%s/%s", directory,
			  entries[i]->d_name);
		if (stat (path, &status) < 0) {
			ret = set_error (error, "cannot stat \"%s\": %s",
					 path, strerror (errno));
		} else if (S_ISREG (status.st_mode)) {
			ret = append_file (files, count, path, error);
		}
		free (path);
		if (ret < 0)
			break;
	}

	for (int i = 0; i < entry_count; i++)
		free (entries[i]);
	free (entries);

	return ret;
}

static int
append_entry(char ***files, size_t *count, const char *directory,
	     const char *entry, char **error)
{
	char *path;
	char *resolved;
	struct stat status;
	size_t path_size;
	int ret;

	if (entry[0] == '/') {
		path = strdup (entry);
	} else {
		path_size = strlen (directory) + strlen (entry) + 2;
		path = malloc (path_size);
		if (path)
			snprintf (path, path_size, "%s/%s", directory, entry);
	}
	if (!path)
		return set_error (error, "out of memory");

	resolved = realpath (path, NULL);
	free (path);
	if (!resolved)
		return set_error (error, "cannot resolve \"%s\": %s",
				  entry, strerror (errno));

	if (stat (resolved, &status) < 0) {
		ret = set_error (error, "cannot stat \"%s\": %s",
				 resolved, strerror (errno));
		free (resolved);
		return ret;
	}

	if (S_ISDIR (status.st_mode))
		ret = append_directory (files, count, resolved, error);
	else if (S_ISREG (status.st_mode))
		ret = append_file (files, count, resolved, error);
	else
		ret = set_error (error, "\"%s\" is not a regular file or directory",
				 resolved);

	free (resolved);

	return ret;
}

int
mok_file_list_load(const char *manifest, char ***files, size_t *count,
		   char **error)
{
	char *manifest_path;
	char *directory;
	char *slash;
	char *line = NULL;
	size_t line_size = 0;
	FILE *file;
	int ret = 0;

	if (error)
		*error = NULL;
	if (!manifest || !files || !count)
		return set_error (error, "invalid file list arguments");

	*files = NULL;
	*count = 0;

	manifest_path = realpath (manifest, NULL);
	if (!manifest_path)
		return set_error (error, "cannot resolve manifest \"%s\": %s",
				  manifest, strerror (errno));

	directory = strdup (manifest_path);
	if (!directory) {
		free (manifest_path);
		return set_error (error, "out of memory");
	}
	slash = strrchr (directory, '/');
	if (slash == directory)
		slash[1] = '\0';
	else if (slash)
		*slash = '\0';
	else
		strcpy (directory, ".");

	file = fopen (manifest_path, "r");
	if (!file) {
		ret = set_error (error, "cannot open manifest \"%s\": %s",
				 manifest_path, strerror (errno));
		goto out;
	}

	while (getline (&line, &line_size, file) >= 0) {
		char *entry = trim (line);

		if (*entry == '\0' || *entry == '#')
			continue;

		ret = append_entry (files, count, directory, entry, error);
		if (ret < 0)
			break;
	}

	if (ret == 0 && ferror (file))
		ret = set_error (error, "cannot read manifest \"%s\": %s",
				 manifest_path, strerror (errno));

	if (ret == 0 && *count == 0)
		ret = set_error (error, "manifest \"%s\" contains no files",
				 manifest_path);

	fclose (file);

out:
	free (line);
	free (directory);
	free (manifest_path);

	if (ret < 0) {
		mok_file_list_free (*files, *count);
		*files = NULL;
		*count = 0;
	}

	return ret;
}

void
mok_file_list_free(char **files, size_t count)
{
	if (!files)
		return;

	for (size_t i = 0; i < count; i++)
		free (files[i]);
	free (files);
}
