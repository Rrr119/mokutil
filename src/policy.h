#ifndef __MOKUTIL_POLICY_H__
#define __MOKUTIL_POLICY_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

typedef enum {
	MOK_POLICY_IMPORT = 0,
	MOK_POLICY_DELETE,
	MOK_POLICY_REVOKE_IMPORT,
	MOK_POLICY_REVOKE_DELETE,
	MOK_POLICY_RESET,
} MokPolicyOperation;

typedef struct MokPolicy MokPolicy;

MokPolicy *mok_policy_load(const char *path, char **error);
void mok_policy_free(MokPolicy *policy);

bool mok_policy_is_enabled(const MokPolicy *policy);
const char *mok_policy_path(const MokPolicy *policy);
const char *mok_policy_error(const MokPolicy *policy);
const char *mok_policy_operation_name(MokPolicyOperation op);

int mok_policy_check_operation(MokPolicy *policy, MokPolicyOperation op);
int mok_policy_check_batch(MokPolicy *policy, MokPolicyOperation op,
			   char *const files[], size_t count);
int mok_policy_check_cert(MokPolicy *policy, MokPolicyOperation op,
			  const char *path, const void *der, size_t der_size);
int mok_policy_check_hash(MokPolicy *policy, MokPolicyOperation op,
			  const char *hash);

void mok_policy_print(const MokPolicy *policy, FILE *out);

#endif /* __MOKUTIL_POLICY_H__ */
