#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "policy.h"

#define POLICY_VERSION_STRING "1"
#define SHA256_DIGEST_SIZE 32
#define POLICY_MAX_BATCH 4096
#define POLICY_DEFAULT_BATCH 64
#define POLICY_ERROR_SIZE 512
#define SHA256_HEX_SIZE (SHA256_DIGEST_SIZE * 2 + 1)

struct MokPolicy {
	bool enabled;
	bool import_allowed;
	bool delete_allowed;
	bool revoke_import_allowed;
	bool revoke_delete_allowed;
	bool reset_allowed;
	bool require_ca;
	size_t max_batch;
	char *path;
	char **allow_paths;
	size_t allow_paths_count;
	char **deny_paths;
	size_t deny_paths_count;
	char **allow_fingerprints;
	size_t allow_fingerprints_count;
	char **deny_fingerprints;
	size_t deny_fingerprints_count;
	char error[POLICY_ERROR_SIZE];
};

static void policy_error(MokPolicy *policy, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void
policy_error(MokPolicy *policy, const char *fmt, ...)
{
	va_list ap;

	va_start (ap, fmt);
	vsnprintf (policy->error, sizeof (policy->error), fmt, ap);
	va_end (ap);
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
add_string(char ***list, size_t *count, const char *value)
{
	char **new_list;
	char *copy;

	copy = strdup (value);
	if (!copy)
		return -1;

	new_list = realloc (*list, (*count + 1) * sizeof (**list));
	if (!new_list) {
		free (copy);
		return -1;
	}

	new_list[*count] = copy;
	*list = new_list;
	(*count)++;

	return 0;
}

static bool
list_contains(char *const list[], size_t count, const char *value)
{
	for (size_t i = 0; i < count; i++) {
		if (strcasecmp (list[i], value) == 0)
			return true;
	}

	return false;
}

static bool
path_is_under(const char *path, const char *prefix)
{
	size_t prefix_len = strlen (prefix);

	if (strncmp (path, prefix, prefix_len) != 0)
		return false;

	return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

static char *
canonical_path(const char *path, char *error, size_t error_size)
{
	char *resolved;

	if (path[0] != '/') {
		snprintf (error, error_size, "path \"%s\" is not absolute", path);
		return NULL;
	}

	resolved = realpath (path, NULL);
	if (!resolved)
		snprintf (error, error_size, "cannot resolve path \"%s\": %s",
			  path, strerror (errno));

	return resolved;
}

static int
parse_action(const char *value, bool *result)
{
	if (strcasecmp (value, "allow") == 0 ||
	    strcasecmp (value, "true") == 0 ||
	    strcasecmp (value, "yes") == 0 ||
	    strcmp (value, "1") == 0) {
		*result = true;
		return 0;
	}

	if (strcasecmp (value, "deny") == 0 ||
	    strcasecmp (value, "false") == 0 ||
	    strcasecmp (value, "no") == 0 ||
	    strcmp (value, "0") == 0) {
		*result = false;
		return 0;
	}

	return -1;
}

static int
normalize_fingerprint(const char *value, char output[SHA256_HEX_SIZE])
{
	size_t length = 0;

	for (const char *ptr = value; *ptr; ptr++) {
		if (*ptr == ':')
			continue;
		if (!((*ptr >= '0' && *ptr <= '9') ||
		      (*ptr >= 'a' && *ptr <= 'f') ||
		      (*ptr >= 'A' && *ptr <= 'F')))
			return -1;
		if (length >= SHA256_HEX_SIZE - 1)
			return -1;
		output[length++] = (char)tolower ((unsigned char)*ptr);
	}

	if (length != SHA256_DIGEST_SIZE * 2)
		return -1;

	output[length] = '\0';

	return 0;
}

static int
parse_positive_size(const char *value, size_t *result)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul (value, &end, 10);
	if (errno != 0 || !end || *end != '\0' || parsed == 0 ||
	    parsed > POLICY_MAX_BATCH)
		return -1;

	*result = (size_t)parsed;

	return 0;
}

static int
policy_parse_line(MokPolicy *policy, unsigned int line_number, char *line)
{
	char *key, *value;
	char *path;
	char fingerprint[SHA256_HEX_SIZE];
	char path_error[POLICY_ERROR_SIZE];
	bool *action = NULL;
	bool parsed_action;
	size_t parsed_size;

	line = trim (line);
	if (*line == '\0' || *line == '#')
		return 0;

	key = line;
	value = key;
	while (*value && *value != ' ' && *value != '\t' && *value != '=')
		value++;
	if (!*value) {
		policy_error (policy, "line %u: missing value", line_number);
		return -1;
	}
	*value++ = '\0';
	value = trim (value);
	if (*value == '=') {
		value++;
		value = trim (value);
	}

	if (*key == '\0' || *value == '\0') {
		policy_error (policy, "line %u: malformed directive",
			      line_number);
		return -1;
	}

	for (char *ptr = key; *ptr; ptr++)
		*ptr = (char)tolower ((unsigned char)*ptr);

	if (strcmp (key, "version") == 0) {
		if (strcmp (value, POLICY_VERSION_STRING) == 0)
			return 0;
		policy_error (policy, "line %u: unsupported policy version \"%s\"",
			      line_number, value);
		return -1;
	}

	if (strcmp (key, "import") == 0) {
		action = &policy->import_allowed;
	} else if (strcmp (key, "delete") == 0) {
		action = &policy->delete_allowed;
	} else if (strcmp (key, "revoke") == 0) {
		if (parse_action (value, &parsed_action) < 0) {
			policy_error (policy,
				      "line %u: invalid action \"%s\"",
				      line_number, value);
			return -1;
		}
		policy->revoke_import_allowed = parsed_action;
		policy->revoke_delete_allowed = parsed_action;
		return 0;
	} else if (strcmp (key, "revoke-import") == 0) {
		action = &policy->revoke_import_allowed;
	} else if (strcmp (key, "revoke-delete") == 0) {
		action = &policy->revoke_delete_allowed;
	} else if (strcmp (key, "reset") == 0) {
		action = &policy->reset_allowed;
	}

	if (action) {
		if (parse_action (value, action) < 0) {
			policy_error (policy,
				      "line %u: invalid action \"%s\"",
				      line_number, value);
			return -1;
		}
		return 0;
	}

	if (strcmp (key, "require-ca") == 0) {
		if (parse_action (value, &parsed_action) < 0) {
			policy_error (policy,
				      "line %u: invalid boolean \"%s\"",
				      line_number, value);
			return -1;
		}
		policy->require_ca = parsed_action;
		return 0;
	}

	if (strcmp (key, "max-batch") == 0) {
		if (parse_positive_size (value, &parsed_size) < 0) {
			policy_error (policy,
				      "line %u: max-batch must be between 1 and %u",
				      line_number, POLICY_MAX_BATCH);
			return -1;
		}
		policy->max_batch = parsed_size;
		return 0;
	}

	if (strcmp (key, "allow-path") == 0 ||
	    strcmp (key, "deny-path") == 0) {
		path = canonical_path (value, path_error, sizeof (path_error));
		if (!path) {
			policy_error (policy, "line %u: %s", line_number,
				      path_error);
			return -1;
		}
		if (strcmp (key, "allow-path") == 0)
			parsed_size = 0;
		else
			parsed_size = 1;
		if (parsed_size == 0) {
			int rc = add_string (&policy->allow_paths,
					     &policy->allow_paths_count, path);
			free (path);
			if (rc < 0) {
				policy_error (policy,
					      "line %u: out of memory",
					      line_number);
				return -1;
			}
		} else {
			int rc = add_string (&policy->deny_paths,
					     &policy->deny_paths_count, path);
			free (path);
			if (rc < 0) {
				policy_error (policy,
					      "line %u: out of memory",
					      line_number);
				return -1;
			}
		}
		return 0;
	}

	if (strcmp (key, "allow-sha256") == 0 ||
	    strcmp (key, "deny-sha256") == 0) {
		if (normalize_fingerprint (value, fingerprint) < 0) {
			policy_error (policy,
				      "line %u: invalid SHA-256 fingerprint",
				      line_number);
			return -1;
		}
		if (strcmp (key, "allow-sha256") == 0) {
			if (add_string (&policy->allow_fingerprints,
					&policy->allow_fingerprints_count,
					fingerprint) < 0) {
				policy_error (policy,
					      "line %u: out of memory",
					      line_number);
				return -1;
			}
		} else {
			if (add_string (&policy->deny_fingerprints,
					&policy->deny_fingerprints_count,
					fingerprint) < 0) {
				policy_error (policy,
					      "line %u: out of memory",
					      line_number);
				return -1;
			}
		}
		return 0;
	}

	policy_error (policy, "line %u: unknown directive \"%s\"",
		      line_number, key);

	return -1;
}

static int
policy_parse_file(MokPolicy *policy, FILE *file)
{
	char *line = NULL;
	size_t line_size = 0;
	unsigned int line_number = 0;
	bool version_seen = false;
	bool import_seen = false;
	bool delete_seen = false;
	bool revoke_seen = false;
	bool revoke_import_seen = false;
	bool revoke_delete_seen = false;
	bool reset_seen = false;
	bool require_ca_seen = false;
	bool max_batch_seen = false;
	int rc;

	while ((rc = getline (&line, &line_size, file)) >= 0) {
		char *trimmed;
		char key[64];
		char *key_end;
		size_t key_len;

		line_number++;
		trimmed = trim (line);
		if (*trimmed == '\0' || *trimmed == '#')
			continue;

		key_end = strpbrk (trimmed, "= \t");
		key_len = key_end ? (size_t)(key_end - trimmed) :
				   strlen (trimmed);
		if (key_len == 0 || key_len >= sizeof (key)) {
			policy_error (policy, "line %u: invalid directive",
				      line_number);
			goto fail;
		}
		memcpy (key, trimmed, key_len);
		key[key_len] = '\0';
		for (size_t i = 0; i < key_len; i++)
			key[i] = (char)tolower ((unsigned char)key[i]);

		if (strcmp (key, "version") == 0) {
			if (version_seen) {
				policy_error (policy,
					      "line %u: duplicate version",
					      line_number);
				goto fail;
			}
			version_seen = true;
		} else if (strcmp (key, "import") == 0) {
			if (import_seen) {
				policy_error (policy,
					      "line %u: duplicate import rule",
					      line_number);
				goto fail;
			}
			import_seen = true;
		} else if (strcmp (key, "delete") == 0) {
			if (delete_seen) {
				policy_error (policy,
					      "line %u: duplicate delete rule",
					      line_number);
				goto fail;
			}
			delete_seen = true;
		} else if (strcmp (key, "revoke") == 0) {
			if (revoke_seen || revoke_import_seen || revoke_delete_seen) {
				policy_error (policy,
					      "line %u: duplicate revoke rule",
					      line_number);
				goto fail;
			}
			revoke_seen = true;
		} else if (strcmp (key, "revoke-import") == 0) {
			if (revoke_seen || revoke_import_seen) {
				policy_error (policy,
					      "line %u: duplicate revoke-import rule",
					      line_number);
				goto fail;
			}
			revoke_import_seen = true;
		} else if (strcmp (key, "revoke-delete") == 0) {
			if (revoke_seen || revoke_delete_seen) {
				policy_error (policy,
					      "line %u: duplicate revoke-delete rule",
					      line_number);
				goto fail;
			}
			revoke_delete_seen = true;
		} else if (strcmp (key, "reset") == 0) {
			if (reset_seen) {
				policy_error (policy,
					      "line %u: duplicate reset rule",
					      line_number);
				goto fail;
			}
			reset_seen = true;
		} else if (strcmp (key, "require-ca") == 0) {
			if (require_ca_seen) {
				policy_error (policy,
					      "line %u: duplicate require-ca rule",
					      line_number);
				goto fail;
			}
			require_ca_seen = true;
		} else if (strcmp (key, "max-batch") == 0) {
			if (max_batch_seen) {
				policy_error (policy,
					      "line %u: duplicate max-batch rule",
					      line_number);
				goto fail;
			}
			max_batch_seen = true;
		}

		if (policy_parse_line (policy, line_number, trimmed) < 0)
			goto fail;
	}

	if (ferror (file)) {
		policy_error (policy, "failed to read policy: %s",
			      strerror (errno));
		goto fail;
	}

	if (!version_seen) {
		policy_error (policy, "missing required version directive");
		goto fail;
	}

	for (size_t i = 0; i < policy->allow_fingerprints_count; i++) {
		if (list_contains (policy->deny_fingerprints,
				   policy->deny_fingerprints_count,
				   policy->allow_fingerprints[i])) {
			policy_error (policy,
				      "fingerprint %s is both allowed and denied",
				      policy->allow_fingerprints[i]);
			goto fail;
		}
	}

	free (line);

	return 0;

fail:
	free (line);

	return -1;
}

MokPolicy *
mok_policy_load(const char *path, char **error)
{
	MokPolicy *policy;
	FILE *file = NULL;

	if (error)
		*error = NULL;

	policy = calloc (1, sizeof (*policy));
	if (!policy) {
		if (error)
			*error = strdup ("out of memory");
		return NULL;
	}

	policy->max_batch = POLICY_DEFAULT_BATCH;

	if (!path) {
		policy->enabled = false;
		return policy;
	}

	policy->enabled = true;
	policy->path = strdup (path);
	if (!policy->path) {
		policy_error (policy, "out of memory");
		goto fail;
	}

	file = fopen (path, "r");
	if (!file) {
		policy_error (policy, "cannot open policy \"%s\": %s",
			      path, strerror (errno));
		goto fail;
	}

	if (policy_parse_file (policy, file) < 0)
		goto fail;

	fclose (file);

	return policy;

fail:
	if (file)
		fclose (file);
	if (error)
		*error = strdup (policy->error);
	mok_policy_free (policy);

	return NULL;
}

void
mok_policy_free(MokPolicy *policy)
{
	if (!policy)
		return;

	free (policy->path);
	for (size_t i = 0; i < policy->allow_paths_count; i++)
		free (policy->allow_paths[i]);
	free (policy->allow_paths);
	for (size_t i = 0; i < policy->deny_paths_count; i++)
		free (policy->deny_paths[i]);
	free (policy->deny_paths);
	for (size_t i = 0; i < policy->allow_fingerprints_count; i++)
		free (policy->allow_fingerprints[i]);
	free (policy->allow_fingerprints);
	for (size_t i = 0; i < policy->deny_fingerprints_count; i++)
		free (policy->deny_fingerprints[i]);
	free (policy->deny_fingerprints);
	free (policy);
}

bool
mok_policy_is_enabled(const MokPolicy *policy)
{
	return policy && policy->enabled;
}

const char *
mok_policy_path(const MokPolicy *policy)
{
	return policy ? policy->path : NULL;
}

const char *
mok_policy_error(const MokPolicy *policy)
{
	if (!policy)
		return "policy is not loaded";

	return policy->error;
}

const char *
mok_policy_operation_name(MokPolicyOperation op)
{
	switch (op) {
	case MOK_POLICY_IMPORT:
		return "import";
	case MOK_POLICY_DELETE:
		return "delete";
	case MOK_POLICY_REVOKE_IMPORT:
		return "revoke-import";
	case MOK_POLICY_REVOKE_DELETE:
		return "revoke-delete";
	case MOK_POLICY_RESET:
		return "reset";
	}

	return "unknown";
}

int
mok_policy_check_operation(MokPolicy *policy, MokPolicyOperation op)
{
	bool allowed;

	if (!mok_policy_is_enabled (policy))
		return 0;

	switch (op) {
	case MOK_POLICY_IMPORT:
		allowed = policy->import_allowed;
		break;
	case MOK_POLICY_DELETE:
		allowed = policy->delete_allowed;
		break;
	case MOK_POLICY_REVOKE_IMPORT:
		allowed = policy->revoke_import_allowed;
		break;
	case MOK_POLICY_REVOKE_DELETE:
		allowed = policy->revoke_delete_allowed;
		break;
	case MOK_POLICY_RESET:
		allowed = policy->reset_allowed;
		break;
	default:
		allowed = false;
		break;
	}

	if (!allowed) {
		policy_error (policy, "operation \"%s\" is denied by policy",
			      mok_policy_operation_name (op));
		return -1;
	}

	return 0;
}

int
mok_policy_check_batch(MokPolicy *policy, MokPolicyOperation op,
		       char *const files[], size_t count)
{
	char path_error[POLICY_ERROR_SIZE];

	if (!mok_policy_is_enabled (policy))
		return 0;

	if (count > policy->max_batch) {
		policy_error (policy, "batch has %zu files but policy allows %zu",
			      count, policy->max_batch);
		return -1;
	}

	if (op != MOK_POLICY_IMPORT && op != MOK_POLICY_DELETE)
		return 0;

	for (size_t i = 0; i < count; i++) {
		char *resolved;
		bool path_allowed = policy->allow_paths_count == 0;
		bool path_denied = false;

		resolved = canonical_path (files[i], path_error,
					   sizeof (path_error));
		if (!resolved) {
			policy_error (policy, "%s", path_error);
			return -1;
		}

		for (size_t j = 0; j < policy->allow_paths_count; j++) {
			if (path_is_under (resolved, policy->allow_paths[j])) {
				path_allowed = true;
				break;
			}
		}
		for (size_t j = 0; j < policy->deny_paths_count; j++) {
			if (path_is_under (resolved, policy->deny_paths[j])) {
				path_denied = true;
				break;
			}
		}

		if (!path_allowed || path_denied) {
			policy_error (policy, "path \"%s\" is not permitted",
				      resolved);
			free (resolved);
			return -1;
		}
		free (resolved);
	}

	return 0;
}

static int
cert_fingerprint(const void *der, size_t der_size,
		 char fingerprint[SHA256_HEX_SIZE])
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size = 0;

	if (!der || der_size == 0 ||
	    !EVP_Digest (der, der_size, digest, &digest_size,
			 EVP_sha256 (), NULL) ||
	    digest_size != SHA256_DIGEST_SIZE)
		return -1;

	for (unsigned int i = 0; i < digest_size; i++)
		snprintf (fingerprint + i * 2, 3, "%02x", digest[i]);
	fingerprint[digest_size * 2] = '\0';

	return 0;
}

int
mok_policy_check_cert(MokPolicy *policy, MokPolicyOperation op,
		      const char *path, const void *der, size_t der_size)
{
	char fingerprint[SHA256_HEX_SIZE];

	if (!mok_policy_is_enabled (policy))
		return 0;

	if (op != MOK_POLICY_IMPORT && op != MOK_POLICY_DELETE)
		return 0;

	if (cert_fingerprint (der, der_size, fingerprint) < 0) {
		policy_error (policy, "cannot calculate fingerprint for \"%s\"",
			      path);
		return -1;
	}

	if (list_contains (policy->deny_fingerprints,
			   policy->deny_fingerprints_count, fingerprint)) {
		policy_error (policy, "certificate \"%s\" (%s) is denied",
			      path, fingerprint);
		return -1;
	}

	if (policy->allow_fingerprints_count > 0 &&
	    !list_contains (policy->allow_fingerprints,
			    policy->allow_fingerprints_count, fingerprint)) {
		policy_error (policy, "certificate \"%s\" (%s) is not allowed",
			      path, fingerprint);
		return -1;
	}

	if (op == MOK_POLICY_IMPORT && policy->require_ca) {
		const unsigned char *input = der;
		X509 *cert = d2i_X509 (NULL, &input, der_size);
		int is_ca;

		if (!cert) {
			policy_error (policy,
				      "certificate \"%s\" is not valid DER",
				      path);
			return -1;
		}

		is_ca = X509_check_ca (cert);
		X509_free (cert);
		if (is_ca <= 0) {
			policy_error (policy,
				      "certificate \"%s\" is not a CA certificate",
				      path);
			return -1;
		}
	}

	return 0;
}

int
mok_policy_check_hash(MokPolicy *policy, MokPolicyOperation op,
		      const char *hash)
{
	const char *value = hash;
	char fingerprint[SHA256_HEX_SIZE];
	bool restricted;

	if (!mok_policy_is_enabled (policy))
		return 0;

	if (op != MOK_POLICY_IMPORT && op != MOK_POLICY_DELETE)
		return 0;

	restricted = policy->allow_fingerprints_count > 0 ||
		     policy->deny_fingerprints_count > 0;
	if (!restricted)
		return 0;

	if (strncasecmp (value, "sha256:", 7) == 0)
		value += 7;

	if (normalize_fingerprint (value, fingerprint) < 0) {
		policy_error (policy,
			      "hash requests require a SHA-256 digest when the policy has hash rules");
		return -1;
	}

	if (list_contains (policy->deny_fingerprints,
			   policy->deny_fingerprints_count, fingerprint)) {
		policy_error (policy, "hash %s is denied by policy", fingerprint);
		return -1;
	}

	if (policy->allow_fingerprints_count > 0 &&
	    !list_contains (policy->allow_fingerprints,
			    policy->allow_fingerprints_count, fingerprint)) {
		policy_error (policy, "hash %s is not allowed by policy",
			      fingerprint);
		return -1;
	}

	return 0;
}

void
mok_policy_print(const MokPolicy *policy, FILE *out)
{
	if (!mok_policy_is_enabled (policy)) {
		fprintf (out, "MOK policy: disabled (legacy behavior)\n");
		return;
	}

	fprintf (out, "MOK policy: %s\n", policy->path);
	fprintf (out, "  import: %s\n",
		 policy->import_allowed ? "allow" : "deny");
	fprintf (out, "  delete: %s\n",
		 policy->delete_allowed ? "allow" : "deny");
	fprintf (out, "  revoke-import: %s\n",
		 policy->revoke_import_allowed ? "allow" : "deny");
	fprintf (out, "  revoke-delete: %s\n",
		 policy->revoke_delete_allowed ? "allow" : "deny");
	fprintf (out, "  reset: %s\n",
		 policy->reset_allowed ? "allow" : "deny");
	fprintf (out, "  require-ca: %s\n",
		 policy->require_ca ? "yes" : "no");
	fprintf (out, "  max-batch: %zu\n", policy->max_batch);
	fprintf (out, "  allow-paths: %zu\n", policy->allow_paths_count);
	fprintf (out, "  deny-paths: %zu\n", policy->deny_paths_count);
	fprintf (out, "  allow-sha256: %zu\n",
		 policy->allow_fingerprints_count);
	fprintf (out, "  deny-sha256: %zu\n",
		 policy->deny_fingerprints_count);
}
