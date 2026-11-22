#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir=$(pwd)
binary="$build_dir/policy_test.tmp"
cc=${CC:-cc}
openssl_flags=$(${PKG_CONFIG:-pkg-config} --cflags --libs openssl)

cleanup()
{
	rm -f "$binary"
}
trap cleanup EXIT HUP INT TERM

"$cc" ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Werror \
	-I"$script_dir/../src" \
	"$script_dir/policy_test.c" \
	"$script_dir/../src/policy.c" \
	"$script_dir/../src/filelist.c" \
	-o "$binary" $openssl_flags

"$binary"
