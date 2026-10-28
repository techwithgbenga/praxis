# Fuzz targets for `praxis-types`

- `decode_object`: throws arbitrary bytes at `praxis_types::decode_object`
  (`docs/IMPLEMENTATION_PLAN.md` M1-02/M1-10). The only invariant is "never
  panics, never hangs" — `Err` is always a fine outcome for untrusted input.

## Running

```bash
rustup toolchain install nightly   # cargo-fuzz needs nightly for ASan
cargo install cargo-fuzz
just fuzz-smoke                    # 60s per target, from the repo root
# or directly:
cargo +nightly fuzz run --fuzz-dir crates/praxis-types/fuzz decode_object -- -max_total_time=60
```

## Known issue: Windows + AddressSanitizer

On Windows, running (not building) a cargo-fuzz target can fail with
`STATUS_DLL_NOT_FOUND` or `STATUS_DLL_INIT_FAILED` even though the build
itself succeeds. Both are AddressSanitizer runtime problems, not bugs in this
target:

- `STATUS_DLL_NOT_FOUND`: `clang_rt.asan_dynamic-x86_64.dll` isn't on `PATH`.
  It ships with Visual Studio's C++ Build Tools, e.g.
  `...\VC\Tools\MSVC\<version>\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll`
  — add that directory to `PATH`.
- `STATUS_DLL_INIT_FAILED`: the DLL loads but its ABI doesn't match what the
  nightly `rustc`'s LLVM sanitizer instrumentation expects — a version
  mismatch between the installed MSVC toolset's `clang_rt` and whatever LLVM
  version the current nightly was built against. We hit exactly this on a
  machine with only VS2019 Build Tools (MSVC 14.29) installed, and did not
  chase down a matching standalone LLVM install (diminishing returns for a
  dev-machine-only problem).

This does not block anything: GitHub Actions' `ubuntu-latest` runners have a
working ASan toolchain out of the box, which is where `just fuzz-smoke` and
the (future, M1-10) nightly 30-minute soak actually run. If you hit this
locally on Windows, either fix the DLL pairing yourself or just trust CI.
