# POSIX shell dot script with useful helper functions for various test
# scripts
#
# Variables used throughout these helper functions:
#   * pfx_fn: short filename-safe (no whitespace) string to add to
#     generated file names

# called by the helper functions below when something goes wrong and
# the test can't continue.  it uses t4s_bailout by default but you can
# redefine the function if you are not using tap4sh.
#
# args:
#   * 1:  a description of the problem
#
abort_test() {
    t4s_bailout "$@"
}

# wrapper around t4s_testcase used to run test cases.  you can
# redefine this if tap4sh is not being used
testcase() {
    t4s_testcase "$@"
}

# wrapper around t4s_log used to log messages in test cases.  you can
# redefine this if tap4sh is not being used.
testcase_log() {
    t4s_log "$@"
}

# Output each permutation of the given arguments, one per line.  Each
# item is separated by a space.
#
# For example, 'permutations a b c' outputs:
#
# a b c
# a c b
# b a c
# b c a
# c a b
# c b a
#
# Note that this is run in a subshell to protect the caller's
# environment (and so that recursive calls don't mess up the caller's
# variables).
#
# args:
#   * 1 through n:  items to permute.  these MUST NOT contain any IFS
#     characters (whitespace)
#
permutations() (
    [ "$#" -gt 0 ] || { pecho ""; return 0; }
    i=0
    for x in "$@"; do
        i=$((i+1))
        j=0
        args=
        for y in "$@"; do
            j=$((j+1))
            [ "${i}" -ne "${j}" ] || continue
            args=${args}\ ${y}
        done
        eval "permutations${args}" | while IFS= read -r line; do
            pecho "${x}${line:+ ${line}}"
        done
    done
)

# scrub the database and the cache dir to clean out data from a
# previous run, then copy the named files to the cache directory
#
# args:
#   * 1:  cache directory
#   * 2 through n:  files to copy
#
reset_state() {
    (
        testcase_log "resetting state..."
        cache_dir=$1; shift
        try rm -rf "${cache_dir}"
        try mkdir -p "${cache_dir}"
        try run "${pfx_fn}rcli-x-t" rcli -x -t "${cache_dir}" -y
        try cp "$@" "${cache_dir}"
    ) || abort_test "unable to reset test state"
}

# add all given files to the database in the given order.  if any add
# fails an error message will be printed (via try) but the script
# won't exit -- it will continue adding the remaining files and the
# function will return non-0
#
# args:
#   * 1:  cache directory
#   * 2 through n:  files from the cache directory to add.  if the
#     filename matches ta-*.cer then it is added as a trust anchor.
add() (
    cache_dir=$1; shift
    ret=0
    for f in "$@"; do
        testcase_log "adding file ${f}..."
        case ${f} in
            ta.cer|ta-*.cer) add_flag=-F;;
            *) add_flag=-f;;
        esac
        # TODO: figure out how to distinguish invalid added object
        # from an error during the add process and call abort_test if
        # there's an error
        (try run "${pfx_fn}rcli-${f}" \
             rcli -s -y "${add_flag}" "${cache_dir}"/"${f}") || ret=1
    done
    exit "${ret}"
)

reset_and_add() {
    reset_state "$@"
    add "$@"
}

# print the sorted args, one arg per line
sort_args() { printf %s\\n "$@" | sort; }

# check if the expected set of files (and only the expected set) were
# accepted
#
# args:
#   * 1 through n:  each argument is an alternative list (whitespace
#     separated) of acceptable files.  for example:
#         check_accepted "foo bar" "baz bif"
#     means that either (foo, bar) or (baz, bif) in the database are
#     acceptable
#
check_accepted() {
    check_accepted_valid=$(
        try run "${pfx_fn}query_cert" query -n -t cert -d filename
        try run "${pfx_fn}query_roa" query -n -t roa -d filename
    ) || abort_test "unable to list valid files"
    check_accepted_valid=$(sort_args ${check_accepted_valid})
    check_accepted_fail_part="expected files"
    check_accepted_fail=
    for check_accepted_expected in "$@"; do
        check_accepted_expected=$(sort_args ${check_accepted_expected})
        [ "${check_accepted_expected}" = "${check_accepted_valid}" ] && exit 0
        check_accepted_fail=${check_accepted_fail}"
  ${check_accepted_fail_part}: $(printf " %s" ${check_accepted_expected})"
        check_accepted_fail_part="            or"
    done
    log "valid files differs from expected"
    while IFS= read -r check_accepted_line; do
        log "${check_accepted_line}"
    done <<EOF
  valid files:    $(printf " %s" ${check_accepted_valid})${check_accepted_fail}
EOF
    return 1
}

# reset the test state, then add files, then check which ones were
# accepted
#
# args:
#   * 1: cache directory
#   * 2: files to add (whitespace separated).  errors adding a file
#     are ignored.
#   * 3 through n: args passed to check_accepted
reset_add_check() {
    reset_and_add "${1}" ${2} || true; shift; shift
    check_accepted "$@"
}

# iterate through all permutations of files to add.  for each
# permutation, run reset_add_check as a testcase.
#
# args:
#   * 1: parent of cache directory.  a subdirectory underneath this
#     (named after the permutation number) will be used as the cache
#     directory
#   * 2: files to permute and add (whitespace separated)
#   * 3 through n: passed as args 3 through n to reset_add_check
test_perms() {
    test_perms_cache_dir=${1}; shift
    test_perms_add=${1}; shift
    test_perms_p=0
    while IFS= read -r test_perms_perm; do
        test_perms_p=$((test_perms_p+1))
        testcase "${pfx}permutation ${test_perms_p} (${test_perms_perm})" \
            'reset_add_check "$@"' \
            "${test_perms_cache_dir}"/"${test_perms_p}" \
            "${test_perms_perm}" \
            "$@"
    done <<EOF
$(permutations  ${test_perms_add})
EOF
}
