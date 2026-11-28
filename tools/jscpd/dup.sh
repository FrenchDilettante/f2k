#!/bin/sh
# Copy-paste detection over F2K's Rust sources (jscpd, its config in jscpd.json).
#
#   tools/jscpd/dup.sh           scan; fail when the duplicated lines grow past the baseline
#   tools/jscpd/dup.sh --update  scan and write today's numbers as the new baseline
#
# The ratchet is on the total of duplicated lines (baseline-lines), not on individual clones:
# an edit inside an accepted clone splits it into new fingerprints, which a per-clone gate would
# report as "new" though nothing was copied. The per-clone comparison (baseline.json) is printed
# as a hint, never as a failure. The reports land in target/jscpd/ (json and html).
#
# Run make dup-update after merges that move code (a split file, a moved module), or the moved
# clones count as new and the baseline drifts.
#
# jscpd (a Rust crate) is built on first use with cargo install --locked into target/tools/jscpd/
# and reused while it is the pinned version; nothing is installed globally.
set -eu

JSCPD_VERSION=5.4.3

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

tools="$root/target/tools/jscpd"
jscpd="$tools/bin/jscpd"
if [ ! -x "$jscpd" ] || [ "$(cat "$tools/version" 2>/dev/null)" != "$JSCPD_VERSION" ]; then
    echo "dup: building jscpd $JSCPD_VERSION into target/tools/jscpd (cargo install --locked)"
    rm -rf "$tools"
    cargo install --quiet --locked --version "$JSCPD_VERSION" --root "$tools" jscpd
    echo "$JSCPD_VERSION" > "$tools/version"
fi
out="$root/target/jscpd"
mkdir -p "$out"

if [ "${1:-}" = "--update" ]; then
    "$jscpd" -c "$here/jscpd.json" --baseline "$here/baseline.json" --update-baseline \
        -r json -o "$out" --silent .
else
    # Clones absent from baseline.json are marked new in the report; --fail-on-new-clones is
    # deliberately not passed (see above).
    "$jscpd" -c "$here/jscpd.json" --baseline "$here/baseline.json" \
        -r console,json,html -o "$out" .
fi

python3 -I - "$out/jscpd-report.json" "$here/baseline-lines" "${1:-}" <<'EOF'
import json, sys

report, baseline_file, mode = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(report))
total = data["statistics"]["total"]
lines, pct, clones = total["duplicatedLines"], total["percentage"], total["clones"]
if mode == "--update":
    with open(baseline_file, "w") as f:
        f.write(f"{lines}\n")
    print(f"dup: baseline set to {lines} duplicated lines ({pct:.2f}%, {clones} clones)")
    sys.exit(0)
baseline = int(open(baseline_file).read().split()[0])
new = [c for c in data["duplicates"] if c.get("isNew")]
for c in new:
    a, b = c["firstFile"], c["secondFile"]
    print(f"dup: new clone, {c['lines']} lines: {a['name']}:{a['start']}-{a['end']}"
          f" <> {b['name']}:{b['start']}-{b['end']}")
print(f"dup: {lines} duplicated lines ({pct:.2f}%, {clones} clones); baseline {baseline}")
if lines > baseline:
    sys.stdout.flush()
    print(f"""dup: FAIL: duplicated lines grew by {lines - baseline} ({baseline} -> {lines}).
  The "new clone" lines above are a hint at where; edits inside old clones show up there too.
  See every clone side by side in target/jscpd/jscpd-report.html.
  To fix it, factor the copy out. To accept a duplicate, add an "ignore" glob for the file in
  tools/jscpd/jscpd.json, or wrap one side in // jscpd:ignore-start ... // jscpd:ignore-end.
  After removing or accepting duplicates, run make dup-update to lower the baseline.""",
          file=sys.stderr)
    sys.exit(1)
if lines < baseline:
    print(f"dup: duplication fell by {baseline - lines} lines; lock it in with make dup-update")
EOF
