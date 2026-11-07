#!/usr/bin/env python3
"""Exercise upstream's actual version initialization with mocked platform I/O.

Compiles hos_version_api.cpp and the real version headers for both pins. This
tests startup's firmware gate, not Switch execution or SSL/account success.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIBS = ROOT / 'Atmosphere-libs'
OLD = 'd3083af1827cd6ca2a96feb9316eb85cd01bae1f'
FILES = [
    'libvapours/include/vapours/ams/ams_target_firmware.h',
    'libstratosphere/include/stratosphere/hos/hos_types.hpp',
    'libstratosphere/source/hos/hos_version_api.cpp',
]
SHIM = r'''
#pragma once
#include <cstdint>
#include <mutex>
#include <stdexcept>
using u32 = std::uint32_t;
using u64 = std::uint64_t;
#include <vapours/ams/ams_target_firmware.h>
#include <stratosphere/hos/hos_types.hpp>
namespace ams {
using Result = u32;
namespace os { using SdkMutex = std::mutex; }
namespace util { struct BitPack64 { u64 value; }; }
namespace exosphere {
struct ApiInfo {
    util::BitPack64 raw;
    ApiInfo(u64 value): raw{value} {}
    ApiInfo(util::BitPack64 value): raw(value) {}
    u32 GetTargetFirmware() const { return static_cast<u32>(raw.value); }
};
}
namespace spl {
enum class ConfigItem { ExosphereApiVersion };
namespace impl {
extern u32 firmware;
inline Result GetConfig(u64 *out, ConfigItem) { *out = firmware; return 0; }
}
}
}
#define R_TRY_CATCH(expr) if ((expr) != 0)
#define R_CATCH_RETHROW(...) throw std::runtime_error("platform error");
#define R_END_TRY_CATCH_WITH_ABORT_UNLESS
#define R_SUCCEED() return 0
#define R_ABORT_UNLESS(expr) do { if ((expr) != 0) throw std::runtime_error("result"); } while (0)
#define AMS_ABORT_UNLESS(expr) do { if (!(expr)) throw std::runtime_error("version abort"); } while (0)
#define AMS_UNUSED(expr) static_cast<void>(expr)
'''
MAIN = r'''
#include "hos_version_api.cpp"
#include <cstdlib>
namespace ams::spl::impl { u32 firmware; }
namespace ams::hos { bool IsUnitTestProgramForSetVersion() { return false; } }
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    ams::spl::impl::firmware = static_cast<u32>(std::strtoul(argv[1], nullptr, 16));
    try { ams::hos::InitializeVersionInternal(false); }
    catch (const std::runtime_error &) { return 86; }
    return ams::hos::GetVersion() == ams::spl::impl::firmware ? 0 : 3;
}
'''


def run(pin, folder, expected):
    folder.mkdir()
    for path in FILES:
        data = subprocess.check_output(['git', '-C', str(LIBS), 'show', f'{pin}:{path}'])
        # Preserve the exact upstream source and headers; only platform I/O is mocked.
        rel = path.split('/include/')[-1] if '/include/' in path else 'hos_version_api.cpp'
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (folder / 'stratosphere.hpp').write_text(SHIM)
    (folder / 'vapours.hpp').write_text('#pragma once\n')
    (folder / 'main.cpp').write_text(MAIN)
    exe = folder / 'firmware-test'
    subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++20', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=undefined', '-fsanitize-undefined-trap-on-error',
                    '-I', str(folder), str(folder / 'main.cpp'), '-o', str(exe)], check=True)
    for version, status in expected.items():
        result = subprocess.run([str(exe), version], check=False)
        if result.returncode != status:
            raise AssertionError(f'{pin} firmware={version}: {result.returncode}, expected {status}')
    print(f'PASS: actual upstream InitializeVersionInternal {pin[:8]} {expected}')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='network-mitm-firmware-') as tmp:
        run(OLD, Path(tmp) / 'old', {'16050000': 0, '17000000': 86, '17000100': 86})
        run('HEAD', Path(tmp) / 'current', {
            '16050000': 0, '17000000': 0, '17000100': 0,
            '17010000': 86, '18000000': 86,
        })
