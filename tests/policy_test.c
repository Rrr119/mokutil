#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "filelist.h"
#include "policy.h"

#define SHA256_HEX_SIZE 65

static int failures;
static const char *current_test;

static void
check(bool condition, const char *fmt, ...)
{
	va_list ap;

	if (condition)
		return;

	fprintf (stderr, "FAIL [%s]: ", current_test);
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fputc ('\n', stderr);
	failures++;
}

static char *
make_temp_dir(void)
{
	char template[] = "/tmp/mokutil-policy-XXXXXX";
	char *path = mkdtemp (template);

	if (!path)
		return NULL;

	return strdup (path);
}

static void
remove_temp_dir(const char *directory)
{
	DIR *dir;
	struct dirent *entry;

	dir = opendir (directory);
	if (dir) {
		while ((entry = readdir (dir)) != NULL) {
			char path[4096];

			if (entry->d_name[0] == '.' &&
			    (entry->d_name[1] == '\0' ||
			     (entry->d_name[1] == '.' &&
			      entry->d_name[2] == '\0')))
				continue;
			snprintf (path, sizeof (path), "%s/%s", directory,
				  entry->d_name);
			unlink (path);
		}
		closedir (dir);
	}
	rmdir (directory);
}

static int
write_file(const char *path, const void *data, size_t size)
{
	FILE *file = fopen (path, "wb");
	size_t written;

	if (!file)
		return -1;
	written = fwrite (data, 1, size, file);
	fclose (file);

	return written == size ? 0 : -1;
}

static int
write_text(const char *path, const char *text)
{
	return write_file (path, text, strlen (text));
}

static int
make_cert(const char *common_name, bool is_ca,
	  unsigned char **der, int *der_size)
{
	EVP_PKEY_CTX *key_context = NULL;
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	X509_EXTENSION *extension = NULL;
	X509_NAME *name;
	unsigned char *cursor;
	int ret = -1;

	key_context = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
	if (!key_context)
		goto out;
	if (EVP_PKEY_keygen_init (key_context) <= 0)
		goto out;
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid (
		    key_context, NID_X9_62_prime256v1) <= 0)
		goto out;
	if (EVP_PKEY_keygen (key_context, &key) <= 0)
		goto out;

	cert = X509_new ();
	if (!cert)
		goto out;
	if (!X509_set_version (cert, 2))
		goto out;
	if (!ASN1_INTEGER_set (X509_get_serialNumber (cert), is_ca ? 1 : 2))
		goto out;
	if (!X509_gmtime_adj (X509_getm_notBefore (cert), 0))
		goto out;
	if (!X509_gmtime_adj (X509_getm_notAfter (cert), 3600))
		goto out;
	if (!X509_set_pubkey (cert, key))
		goto out;

	name = X509_get_subject_name (cert);
	if (!name)
		goto out;
	if (!X509_NAME_add_entry_by_txt (
		    name, "CN", MBSTRING_ASC,
		    (const unsigned char *)common_name, -1, -1, 0))
		goto out;
	if (!X509_set_issuer_name (cert, name))
		goto out;

	extension = X509V3_EXT_conf_nid (
		NULL, NULL, NID_basic_constraints,
		is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
	if (!extension)
		goto out;
	if (!X509_add_ext (cert, extension, -1))
		goto out;

	if (!X509_sign (cert, key, EVP_sha256 ()))
		goto out;

	*der_size = i2d_X509 (cert, NULL);
	if (*der_size <= 0)
		goto out;
	*der = malloc ((size_t)*der_size);
	if (!*der)
		goto out;
	cursor = *der;
	if (i2d_X509 (cert, &cursor) != *der_size) {
		free (*der);
		*der = NULL;
		goto out;
	}

	ret = 0;
out:
	X509_EXTENSION_free (extension);
	X509_free (cert);
	EVP_PKEY_free (key);
	EVP_PKEY_CTX_free (key_context);

	return ret;
}

static void
cert_fingerprint(const unsigned char *der, int der_size,
		 char output[SHA256_HEX_SIZE])
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_size = 0;

	EVP_Digest (der, (size_t)der_size, digest, &digest_size,
		    EVP_sha256 (), NULL);
	for (unsigned int i = 0; i < digest_size; i++)
		sprintf (output + i * 2, "%02x", digest[i]);
	output[digest_size * 2] = '\0';
}

static MokPolicy *
load_policy(const char *path)
{
	MokPolicy *policy;
	char *error = NULL;

	policy = mok_policy_load (path, &error);
	if (!policy) {
		fprintf (stderr, "policy load failed: %s\n",
			 error ? error : "unknown error");
		free (error);
	}

	return policy;
}

static int
test_legacy_configuration(void)
{
	MokPolicy *policy;
	char *files[] = { (char *)"/does/not/exist" };

	current_test = "legacy-no-policy";
	policy = load_policy (NULL);
	if (!policy)
		return -1;

	check (!mok_policy_is_enabled (policy), "legacy policy is enabled");
	check (mok_policy_check_operation (policy, MOK_POLICY_IMPORT) == 0,
	       "legacy import denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_DELETE) == 0,
	       "legacy delete denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_REVOKE_IMPORT) == 0,
	       "legacy revoke-import denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_REVOKE_DELETE) == 0,
	       "legacy revoke-delete denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_RESET) == 0,
	       "legacy reset denied");
	check (mok_policy_check_batch (policy, MOK_POLICY_IMPORT, files, 1) == 0,
	       "legacy batch was checked");
	check (mok_policy_check_cert (policy, MOK_POLICY_IMPORT, "cert",
				      "not-a-cert", 10) == 0,
	       "legacy certificate was checked");

	mok_policy_free (policy);

	return 0;
}

static int
test_allowed_batch_configuration(void)
{
	char *directory = NULL;
	char *policy_path = NULL;
	char *manifest_path = NULL;
	char *ca_path = NULL;
	char *leaf_path = NULL;
	char policy_text[4096];
	char manifest[1024];
	char ca_fingerprint[SHA256_HEX_SIZE];
	char leaf_fingerprint[SHA256_HEX_SIZE];
	unsigned char *ca = NULL;
	unsigned char *leaf = NULL;
	int ca_size = 0, leaf_size = 0;
	char **files = NULL;
	size_t file_count = 0;
	char *error = NULL;
	MokPolicy *policy = NULL;
	int ret = -1;

	current_test = "allowed-batch";

	directory = make_temp_dir ();
	if (!directory)
		goto out;
	if (make_cert ("Test CA", true, &ca, &ca_size) < 0 ||
	    make_cert ("Test Leaf", false, &leaf, &leaf_size) < 0)
		goto out;

	ca_path = malloc (strlen (directory) + sizeof ("/ca.der"));
	leaf_path = malloc (strlen (directory) + sizeof ("/leaf.der"));
	policy_path = malloc (strlen (directory) + sizeof ("/policy.conf"));
	manifest_path = malloc (strlen (directory) + sizeof ("/import.list"));
	if (!ca_path || !leaf_path || !policy_path || !manifest_path)
		goto out;

	sprintf (ca_path, "%s/ca.der", directory);
	sprintf (leaf_path, "%s/leaf.der", directory);
	sprintf (policy_path, "%s/policy.conf", directory);
	sprintf (manifest_path, "%s/import.list", directory);

	if (write_file (ca_path, ca, (size_t)ca_size) < 0 ||
	    write_file (leaf_path, leaf, (size_t)leaf_size) < 0)
		goto out;

	cert_fingerprint (ca, ca_size, ca_fingerprint);
	cert_fingerprint (leaf, leaf_size, leaf_fingerprint);

	snprintf (policy_text, sizeof (policy_text),
		  "version = 1\n"
		  "import allow\n"
		  "delete = allow\n"
		  "max-batch = 2\n"
		  "allow-path %s\n"
		  "allow-sha256 %s\n"
		  "allow-sha256 %s\n",
		  directory, ca_fingerprint, leaf_fingerprint);
	if (write_text (policy_path, policy_text) < 0)
		goto out;

	policy = load_policy (policy_path);
	if (!policy)
		goto out;

	check (mok_policy_check_operation (policy, MOK_POLICY_IMPORT) == 0,
	       "allowed import was denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_DELETE) == 0,
	       "allowed delete was denied");

	snprintf (manifest, sizeof (manifest),
		  "# generated by policy_test\n"
		  "ca.der\n"
		  "leaf.der\n");
	if (write_text (manifest_path, manifest) < 0)
		goto out;
	if (mok_file_list_load (manifest_path, &files, &file_count,
				&error) < 0) {
		fprintf (stderr, "manifest load failed: %s\n",
			 error ? error : "unknown error");
		goto out;
	}

	check (file_count == 2, "manifest has %zu files, expected 2",
	       file_count);
	check (mok_policy_check_batch (policy, MOK_POLICY_IMPORT,
				       files, file_count) == 0,
	       "allowed batch was denied");
	check (mok_policy_check_cert (policy, MOK_POLICY_IMPORT, ca_path,
				      ca, (size_t)ca_size) == 0,
	       "allowed CA was denied");
	check (mok_policy_check_cert (policy, MOK_POLICY_DELETE, leaf_path,
				      leaf, (size_t)leaf_size) == 0,
	       "allowed delete certificate was denied");
	check (mok_policy_check_hash (policy, MOK_POLICY_IMPORT,
				      ca_fingerprint) == 0,
	       "allowed SHA-256 hash was denied");
	check (mok_policy_check_hash (policy, MOK_POLICY_IMPORT,
				      "sha256:00") < 0,
	       "invalid hash was accepted by policy");

	ret = 0;
out:
	if (policy)
		mok_policy_free (policy);
	if (files)
		mok_file_list_free (files, file_count);
	free (error);
	free (ca);
	free (leaf);
	free (ca_path);
	free (leaf_path);
	free (policy_path);
	free (manifest_path);
	if (directory)
		remove_temp_dir (directory);
	free (directory);

	return ret;
}

static int
test_deny_configuration(void)
{
	char *directory = NULL;
	char *cert = NULL;
	char *policy_path = NULL;
	char *deny_path_policy = NULL;
	char *batch_path = NULL;
	char *ca_path = NULL;
	char policy_text[4096];
	char denied_policy[2048];
	char batch_policy[2048];
	char ca_policy[2048];
	char fingerprint[SHA256_HEX_SIZE];
	unsigned char *der = NULL;
	int der_size = 0;
	char *files[] = { NULL };
	char *error = NULL;
	MokPolicy *policy = NULL;
	int ret = -1;

	current_test = "deny-rules";

	directory = make_temp_dir ();
	if (!directory)
		goto out;
	if (make_cert ("Denied Cert", false, &der, &der_size) < 0)
		goto out;

	cert = malloc (strlen (directory) + sizeof ("/denied.der"));
	policy_path = malloc (strlen (directory) + sizeof ("/deny.conf"));
	deny_path_policy = malloc (strlen (directory) + sizeof ("/path.conf"));
	batch_path = malloc (strlen (directory) + sizeof ("/batch.conf"));
	ca_path = malloc (strlen (directory) + sizeof ("/ca.conf"));
	if (!cert || !policy_path || !deny_path_policy || !batch_path ||
	    !ca_path)
		goto out;

	sprintf (cert, "%s/denied.der", directory);
	sprintf (policy_path, "%s/deny.conf", directory);
	sprintf (deny_path_policy, "%s/path.conf", directory);
	sprintf (batch_path, "%s/batch.conf", directory);
	sprintf (ca_path, "%s/ca.conf", directory);
	if (write_file (cert, der, (size_t)der_size) < 0)
		goto out;

	cert_fingerprint (der, der_size, fingerprint);
	snprintf (policy_text, sizeof (policy_text),
		  "version 1\n"
		  "import allow\n"
		  "allow-path %s\n"
		  "deny-sha256 %s\n",
		  directory, fingerprint);
	if (write_text (policy_path, policy_text) < 0)
		goto out;

	policy = load_policy (policy_path);
	if (!policy)
		goto out;
	check (mok_policy_check_cert (policy, MOK_POLICY_IMPORT, cert,
				      der, (size_t)der_size) < 0,
	       "denied fingerprint was accepted");
	check (strstr (mok_policy_error (policy), "denied") != NULL,
	       "deny error does not explain the decision");
	mok_policy_free (policy);
	policy = NULL;

	snprintf (denied_policy, sizeof (denied_policy),
		  "version 1\nimport allow\ndeny-path %s\n", directory);
	if (write_text (deny_path_policy, denied_policy) < 0)
		goto out;
	policy = load_policy (deny_path_policy);
	if (!policy)
		goto out;
	files[0] = cert;
	check (mok_policy_check_batch (policy, MOK_POLICY_IMPORT, files, 1) < 0,
	       "denied path was accepted");
	mok_policy_free (policy);
	policy = NULL;

	snprintf (batch_policy, sizeof (batch_policy),
		  "version 1\nimport allow\nmax-batch 1\nallow-path %s\n",
		  directory);
	if (write_text (batch_path, batch_policy) < 0)
		goto out;
	policy = load_policy (batch_path);
	if (!policy)
		goto out;
	files[0] = cert;
	check (mok_policy_check_batch (policy, MOK_POLICY_IMPORT, files, 2) < 0,
	       "max-batch was not enforced");
	mok_policy_free (policy);
	policy = NULL;

	snprintf (ca_policy, sizeof (ca_policy),
		  "version 1\nimport allow\nrequire-ca yes\n");
	if (write_text (ca_path, ca_policy) < 0)
		goto out;
	policy = load_policy (ca_path);
	if (!policy)
		goto out;
	check (mok_policy_check_cert (policy, MOK_POLICY_IMPORT, cert,
				      der, (size_t)der_size) < 0,
	       "non-CA certificate passed require-ca");

	ret = 0;
out:
	if (policy)
		mok_policy_free (policy);
	free (error);
	free (der);
	free (cert);
	free (policy_path);
	free (deny_path_policy);
	free (batch_path);
	free (ca_path);
	if (directory)
		remove_temp_dir (directory);
	free (directory);

	return ret;
}

static int
test_revoke_configuration(void)
{
	char *directory = NULL;
	char *policy_path = NULL;
	char policy_text[2048];
	char *error = NULL;
	MokPolicy *policy = NULL;
	int ret = -1;

	current_test = "revoke-policy";

	directory = make_temp_dir ();
	if (!directory)
		goto out;
	policy_path = malloc (strlen (directory) + sizeof ("/revoke.conf"));
	if (!policy_path)
		goto out;
	sprintf (policy_path, "%s/revoke.conf", directory);

	snprintf (policy_text, sizeof (policy_text),
		  "version 1\n"
		  "import deny\n"
		  "delete deny\n"
		  "revoke-import allow\n"
		  "revoke-delete deny\n"
		  "reset deny\n");
	if (write_text (policy_path, policy_text) < 0)
		goto out;

	policy = load_policy (policy_path);
	if (!policy)
		goto out;
	check (mok_policy_check_operation (policy, MOK_POLICY_IMPORT) < 0,
	       "import should be denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_REVOKE_IMPORT) == 0,
	       "revoke-import should be allowed");
	check (mok_policy_check_operation (policy, MOK_POLICY_REVOKE_DELETE) < 0,
	       "revoke-delete should be denied");
	check (mok_policy_check_operation (policy, MOK_POLICY_RESET) < 0,
	       "reset should be denied");

	ret = 0;
out:
	if (policy)
		mok_policy_free (policy);
	free (error);
	free (policy_path);
	if (directory)
		remove_temp_dir (directory);
	free (directory);

	return ret;
}

static int
test_invalid_configuration(void)
{
	static const char *invalid[] = {
		"import allow\n",
		"version 2\nimport allow\n",
		"version 1\nimport allow\nimport deny\n",
		"version 1\nunknown-rule allow\n",
		"version 1\nallow-sha256 1234\n",
		"version 1\nrevoke allow\nrevoke-import allow\n",
		"version 1\nmax-batch 0\n",
		"version 1\nimport maybe\n",
		"version 1\nallow-path relative/path\n",
		"version 1\nallow-sha256 "
		"0000000000000000000000000000000000000000000000000000000000000000\n"
		"deny-sha256 "
		"0000000000000000000000000000000000000000000000000000000000000000\n",
	};
	char *directory = NULL;
	char *policy_path = NULL;
	int ret = -1;

	current_test = "invalid-policy";

	directory = make_temp_dir ();
	if (!directory)
		goto out;
	policy_path = malloc (strlen (directory) + sizeof ("/invalid.conf"));
	if (!policy_path)
		goto out;
	sprintf (policy_path, "%s/invalid.conf", directory);

	for (size_t i = 0; i < sizeof (invalid) / sizeof (invalid[0]); i++) {
		char *error = NULL;
		MokPolicy *policy;

		if (write_text (policy_path, invalid[i]) < 0)
			goto out;
		policy = mok_policy_load (policy_path, &error);
		check (policy == NULL, "invalid policy case %zu was accepted", i);
		check (error && *error != '\0',
		       "invalid policy case %zu has no error message", i);
		mok_policy_free (policy);
		free (error);
	}

	ret = 0;
out:
	free (policy_path);
	if (directory)
		remove_temp_dir (directory);
	free (directory);

	return ret;
}

int
main(void)
{
	int failed_before;
	int test_failures = 0;

	printf ("1..5\n");

	failed_before = failures;
	if (test_legacy_configuration () < 0)
		failures++;
	printf ("%s 1 - legacy-no-policy\n",
		failures == failed_before ? "ok" : "not ok");
	if (failures != failed_before)
		test_failures++;

	failed_before = failures;
	if (test_allowed_batch_configuration () < 0)
		failures++;
	printf ("%s 2 - allowed-batch\n",
		failures == failed_before ? "ok" : "not ok");
	if (failures != failed_before)
		test_failures++;

	failed_before = failures;
	if (test_deny_configuration () < 0)
		failures++;
	printf ("%s 3 - deny-rules\n",
		failures == failed_before ? "ok" : "not ok");
	if (failures != failed_before)
		test_failures++;

	failed_before = failures;
	if (test_revoke_configuration () < 0)
		failures++;
	printf ("%s 4 - revoke-policy\n",
		failures == failed_before ? "ok" : "not ok");
	if (failures != failed_before)
		test_failures++;

	failed_before = failures;
	if (test_invalid_configuration () < 0)
		failures++;
	printf ("%s 5 - invalid-policy\n",
		failures == failed_before ? "ok" : "not ok");
	if (failures != failed_before)
		test_failures++;

	return test_failures == 0 ? 0 : 1;
}
