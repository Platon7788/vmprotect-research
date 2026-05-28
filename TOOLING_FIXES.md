# Tooling Fixes & Workarounds

> Applied during 2026-05-28 RE session on CachyOS (GCC 16, LLVM 22, CMake 4.3, Clang 22)

---

## NoVmp Build Fixes

### 1. Capstone: system v5 instead of fetched v6
**File:** `VTIL-Core/Dependencies/capstone/CMakeLists.txt`
```cmake
# Was: FetchContent(https://github.com/aquynh/capstone, tag=...)
# Problem: v6 renamed aarch64 API, broke VTIL-Core ARM64 code
# Fix: use system capstone 5.0.7
add_library(capstone-static INTERFACE)
target_include_directories(capstone-static INTERFACE /usr/include)
target_link_libraries(capstone-static INTERFACE /usr/lib/libcapstone.so)
```

### 2. Keystone LLVM headers: add `<cstdint>`
**Error:** `unknown type name 'intptr_t'` in `llvm/include/llvm/ADT/STLExtras.h`
**Fix:** After cmake fetch, patch:
```bash
KS=$(find build_clang/_deps -name keystone-src -type d)/llvm/include/llvm/ADT/STLExtras.h
sed -i '1a #include <cstdint>' "$KS"
```
**Note:** Must be done AFTER cmake fetches keystone, BEFORE build. Clean build dir removes patches.

### 3. VTIL-Core task.hpp: missing `<utility>`
**Error:** `no member named 'exchange' in namespace 'std'`
**File:** `VTIL-Core/VTIL-Common/includes/vtil/../../util/task.hpp`
**Fix:** Add `#include <utility>` after `#include <memory>`

### 4. Pause calls: Linux compat
**Files:** `NoVmp/main.cpp:321`, `NoVmp/main.cpp:389`
**Fix:** Remove `system("pause")` — Windows-only command

### 5. Compiler: use Clang, not GCC
**Problem:** GCC 16.1.1 stricter than Clang 22.1.5 with old C++ code
**Build command:**
```bash
CC=clang CXX=clang++ cmake -S . -B build_clang -Wno-dev
cmake --build build_clang -j$(nproc)
```

---

## Triton Installation

### Python bindings
```bash
# WRONG: pip install triton  (installs OpenAI ML Triton, v3.7.0)
# RIGHT: Build from source:
git clone https://github.com/JonathanSalwan/Triton.git
cd Triton && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install
```

### Verify:
```python
from triton import TritonContext, ARCH
ctx = TritonContext(ARCH.X86_64)
print("OK")
```

---

## titan Build (Failed)

**Error:** `fatal error: llvm/Analysis/CFLAndersAliasAnalysis.h: No such file or directory`
**Cause:** Requires LLVM 15; system has LLVM 22. `CFLAndersAliasAnalysis` removed in LLVM 16+.
**Verdict:** Not worth patching. Requires significant code rewrite for LLVM 22 API.

---

## VMP3-Disasm Build (Failed)

**Error:** `fatal error: 'triton/api.hpp' file not found`
**Cause:** Old Triton API. `triton::API` class renamed to `TritonContext`.
**Verdict:** Not worth patching. Only disassembles VM bytecode, doesn't decompile.

---

## PIN Download (Failed)

**Error:** Intel URL redirects to 404 (`software.intel.com/sites/landingpage/pintool/downloads/...`)
**Alternative:** Use `rr` (already installed at `/usr/bin/rr`) for Linux process tracing.

---

## PE Reconstruction

**Script:** `/tmp/reconstruct_pe.py` (or recreated from `VMP_INTERNALS.md §9`)

**Key insight:** Dumps capture POST-initialization state. Entry stubs already self-modified.
For pre-modification state, need to capture dumps at process startup before VMP init completes
(impractical with LD_PRELOAD hook).
