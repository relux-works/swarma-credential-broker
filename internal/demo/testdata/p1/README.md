These are synthetic, byte-exact outputs of unmodified user-manager P1 program
bf72a78a2c02ca30d1238e218df2f3318a63b92b (PR75), not operator records or live
qualification. The program pin is out of band and is never a wire revision.

Load demo/tests/test_demo.py at that commit. For each of EXECUTOR_ID and
CODEX_EXECUTOR_ID, take its roster() fixture, select the exact EXECUTORS ID/path
pair and the fixture SHA-256 (`a` repeated 64 times), and call
encoded(validate_roster(roster)). For the attempt, select the same executor in
launch_request(), then call encoded(new_record(roster, roster['accounts'][0],
request, 100.0)). No P1 constant, validator, encoder or constructor is patched.
The attempt's accepted_at is the actual constructor timestamp, so regeneration
has a different timestamp and hash. Both wire revisions must remain the frozen
copy-source value 7d705966aa92acaebea2d55060dcb84ddf7e5031.

manifest.json records the exact input blobs, input SHA-256 values, and output
SHA-256 values. Root namespace admission tests mount the synthetic fixture boot
ID (11111111-1111-1111-1111-111111111111) at /proc/sys/kernel/random/boot_id to
install the roster bytes unchanged. They require an empty disposable /etc and
never operate on a real installation.
