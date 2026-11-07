#!/usr/bin/env bash
# Build with pinned inputs; no network or package upgrades inside the container.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)
source_commit=$(git rev-parse HEAD)
if [[ -n $(git status --porcelain) ]]; then
    echo 'Commit the intended source changes before a release build.' >&2
    exit 1
fi
image=$(python3 -c 'import json; print(json.load(open("BUILD-DEPS.json"))["container"])')
compiler=$(python3 -c 'import json; print(json.load(open("BUILD-DEPS.json"))["compiler"])')
python3 - <<'PY'
import json, subprocess
deps = json.load(open('BUILD-DEPS.json'))
for path, key in [('Atmosphere-libs', 'atmosphere_libs'), ('dependencies/libnx', 'libnx')]:
    sha = subprocess.check_output(['git', '-C', path, 'rev-parse', 'HEAD'], text=True).strip()
    if sha != deps[key] or subprocess.check_output(['git', '-C', path, 'status', '--porcelain']):
        raise SystemExit(f'{path}: initialize the pinned, clean submodule first')
PY
epoch=$(git show -s --format=%ct HEAD)
docker run --rm --network none \
    -e SOURCE_DATE_EPOCH="$epoch" \
    -e NETWORK_MITM_EXPECTED_COMPILER="$compiler" \
    -e GIT_CONFIG_COUNT=3 \
    -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/code \
    -e GIT_CONFIG_KEY_1=safe.directory -e GIT_CONFIG_VALUE_1=/code/Atmosphere-libs \
    -e GIT_CONFIG_KEY_2=core.abbrev -e GIT_CONFIG_VALUE_2=8 \
    -v "$root:/code" -w /code "$image" bash -euc '
        export PATH=/opt/devkitpro/devkitA64/bin:$PATH
        test "$(aarch64-none-elf-g++ --version | head -1)" = "$NETWORK_MITM_EXPECTED_COMPILER"
        make -C dependencies/libnx clean
        make -C dependencies/libnx -j8
        make -C dependencies/libnx install
        make clean
        make -j8 pack
    '
if [[ $(git rev-parse HEAD) != "$source_commit" || -n $(git status --porcelain) ]]; then
    echo 'Source changed during the build; refusing to record release provenance.' >&2
    exit 1
fi
python3 tools/check-binary.py --sd out/sd --output out/binary-check.json
python3 - <<'PY'
import hashlib, json, pathlib, subprocess
def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()
data = json.load(open('BUILD-DEPS.json'))
data.update(source_commit=git('rev-parse', 'HEAD'),
            source_dirty=bool(git('status', '--porcelain')),
            source_date_epoch=int(git('show', '-s', '--format=%ct', 'HEAD')),
            nsp_sha256=hashlib.sha256(pathlib.Path('out/sd/atmosphere/contents/4200000000000666/exefs.nsp').read_bytes()).hexdigest())
pathlib.Path('out/TARGET-BUILD.json').write_text(json.dumps(data, indent=2)+'\n')
PY
