# TVM → FunC decompiler

## !!! Completely vibe-coded. Didn't even look at the code. !!!


A deterministic Python service and compiler-research harness. It accepts a **code-cell BOC** in base64, disassembles it with official TON tooling, reconstructs FunC, and recompiles candidates before reporting success. It does not accept an account/state BOC or require the caller to know the compiler version.

Measured baseline: **74/74 validation** and **53/57 holdout** contracts round-trip to the exact input code hash. This mostly uses explicit assembly preservation: only **21/349 holdout methods** were lifted to high-level FunC. See [the measured results and limitations](research/RESULTS.md).

## Run

Python 3.12+ on Linux x86-64. No Python runtime dependencies. Historical source builds need `cmake`, `make`, `git`, `g++`, `libssl-dev`, and `zlib1g-dev` (install with your system package manager). Bootstrap downloads checksum-pinned official TON release assets and builds the older compilers from immutable source revisions. Use `python3 scripts/bootstrap.py --releases-only` for a faster release-only installation with reduced historical coverage.

```sh
python3 scripts/bootstrap.py
python3 -m decompiler serve --host 127.0.0.1 --port 8080
```

Open http://127.0.0.1:8080/ for the built-in web page. Paste a base64 code-cell BOC and click **Decompile** to see reconstructed FunC, verification status, diagnostics, and the full JSON response. Wrapped base64 is accepted.

Optionally install the `decompiler` command with `python3 -m pip install -e .`.

```sh
curl http://127.0.0.1:8080/v1/decompile \
  -H 'Content-Type: application/json' \
  --data '{"code":"<base64 code-cell BOC>","max_search_time_ms":30000}'
```

The search budget defaults to 30 seconds and accepts 1–30000 milliseconds. Input is limited to 1 MiB, one root, 16384 cells, and depth 512. Ordinary level-zero cells are supported; exotic and levelled cells return a structured error. Compiler paths and arguments are operator-controlled, never request-controlled.

Successful responses include separate `contract` and `stdlib` source strings, the combined standalone `func` string for compatibility, `compiler`, `decompilation`, `diagnostics`, and measured `search` costs. The web page displays contract source first and generated stdlib helpers in a separate expandable section. To save separate files, write `stdlib` to `stdlib.fc` and prepend `#include "stdlib.fc";` to `contract`. `recompiles: true` means the returned source actually compiled. `quality: exact` means its TON cell representation hash matched the input. Similar instruction sequences alone do not establish semantic equivalence. Compatibility with several compiler configurations is reported explicitly; `compiler.version` can be null. `selected_version` identifies the compiler used to validate the returned source, not necessarily its historical origin.

When a compiled reconstruction decodes more methods or simplifies temporary values, the response also includes `readable`, with its own `contract`, `stdlib`, combined `func`, compiler settings, diagnostics, and verification metrics. The web page defaults to this **Readable FunC** view and offers the exact-bytecode source separately. A readable candidate whose code hash differs is explicitly unverified: compilation and structural analysis alone do not prove semantic equivalence. Verification labels always describe the selected source. For the DNS NFT fixture, this exposes all 15 methods including `recv_internal`; the exact view retains 14 high-level methods plus the preserved receiver.

Direct persistent-storage readers and writers are named `load_data` and `store_data`, with all call sites updated and their numeric method IDs preserved. Multiple matching helpers receive ID suffixes to keep names distinct. These are inferred roles, not recovered original names. Receiver arguments use `msg_value`, `in_msg_full`, and `in_msg_body` (plus `balance` when the fourth entry-stack argument is needed).

Wallet V5 reconstruction supports static continuation calls, scoped alternate returns, extension-action loops, signature checks, and action-register operations. Its seven original methods (including both receivers) have a compiled readable view; extracted continuation helpers do not inflate method counts. The exact view retains assembly for the two receivers. Regression tests compare the readable code with the original in the official VM across 19 signed-message and extension-action cases, including storage and action outputs; these tests are not a proof of equivalence for every input.

Generated helpers use standard names where their signatures match, such as `get_data`, `begin_cell`, and `send_raw_message`. Helpers ending in `_raw` expose TVM operand/result order directly. `impure_touch` is the value-returning counterpart of stdlib's modifying `~impure_touch`: its `NOP` declaration prevents the compiler from dropping, moving, or folding the argument. It preserves evaluation order; it is not a contract business-logic operation.

The readable view inlines single-use constants and immutable aliases throughout expressions, calls, returns, and branches. Adjacent single-use computations also inline when evaluation order is preserved, giving expressions such as `if (arg0 == 7)` and `skip_bits(v12, 1)`. Shared or mutable values and computations that could move an effect or exception retain temporaries. Slice-loading chains use modifying calls such as `cs~load_coins()` and `cs~skip_bits(1)` when the previous slice value is no longer needed. Builder expressions use chained calls such as `begin_cell().store_uint(value, 256).store_ref(content).end_cell()`, with long chains split across lines. Raw operand-order helpers remain when chaining would move an effect. Unused results are discarded (with `_` for unused fields of a multi-result call), and surviving local variables are numbered consecutively. Integer literals greater than `2**29` are printed in hexadecimal, except Unix timestamps from 2019-01-01 through 2030-01-01 UTC (inclusive), which stay decimal. The cleaned source is recompiled and has its own verification results; the exact-bytecode view retains scheduling helpers when needed.

Failures have this form:

```json
{"success":false,"error":{"code":"INVALID_BOC","message":"Invalid BOC magic","stage":"boc"},"diagnostics":[]}
```

HTTP status: 400 malformed request/base64/BOC; 413 oversized body; 415 incorrect media type; 422 unsupported reconstruction or exhausted candidate search; 503 unavailable tooling/busy workers; 504 request deadline; 500 internal worker failure.

## Docker

```sh
docker build --platform linux/amd64 -t tvm-decompiler .
docker run --rm -p 127.0.0.1:8080:8080 --name tvm-decompiler tvm-decompiler
```

Open http://127.0.0.1:8080/ for the same web page and API. The first build downloads all ten pinned toolchains and compiles four historical versions; allow time for the C++ builds. Set `--build-arg BUILD_JOBS=8` to change build parallelism (default 4). The final image runs as an unprivileged user and excludes compiler build sources and the contract corpus. To keep the compilation cache across containers, add `-v tvm-decompiler-cache:/var/cache/decompiler` to `docker run`.

### GitHub Container Registry

The [Docker workflow](.github/workflows/docker.yml) builds and checks the web page plus a real decompilation on pull requests. Pushes to the repository's default branch publish `ghcr.io/<owner>/<repo>:latest` and `sha-<full-commit>`; tags matching `v*` publish that tag and the commit tag. Manual runs publish the commit tag, and also `latest` when run on the default branch. Image names use lowercase. Compiler build layers are cached between runs.

Push this project to a GitHub repository with Actions enabled. The workflow authenticates with the automatically supplied `GITHUB_TOKEN` and requests `packages: write`; no personal access token secret is needed. See [GitHub's registry publishing documentation](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images). Package visibility is managed separately in GitHub's package settings; private packages require authentication to pull. This workspace has no Git remote configured, so the workflow must run after the project is pushed to GitHub.

```sh
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/<owner>/<repo>:latest
```

## Developer commands

```sh
python3 -m decompiler disasm contract.boc
python3 -m decompiler decompile contract.boc --debug
python3 -m decompiler detect-compiler contract.boc
python3 -m decompiler verify contract.boc candidate.fc --version 0.4.4
python3 -m decompiler compiler-diff source.fc
python3 -m decompiler corpus inventory orig_func_verified
python3 -m decompiler corpus build orig_func_verified
python3 -m decompiler corpus evaluate orig_func_verified --split holdout
python3 scripts/all_contracts_report.py --root orig_func_verified --output research/all-300
python3 -m unittest discover -s tests -v
```

`--debug` exposes normalized instructions, CFG, generated AST, and compiler rankings. `verify` prints bounded ASM differences. Corpus commands accept `--output` and `--limit`; evaluation accepts `--workers 1` for isolated latency or the default four concurrent requests; the latter is for smoke checks, not full benchmark claims. `orig_func_verified` is read-only to the application.

## Architecture

- `boc.py`: strict BOC decoding, CRC32C, ordinary-cell representation hashing.
- `toolchain.py`: pinned official compiler/Fift execution, isolated temporary directories, timeouts and compilation cache.
- `asm.py`: tokenized instructions, constants, and nested continuation blocks; safe layout normalization.
- `ir.py`: CFG and conservative symbolic stack execution; unsupported semantics remain explicit.
- `func.py`: FunC AST, printer, and bounded AST alternatives.
- `compare.py`: instruction/constant/continuation and CFG similarity measurements.
- `fingerprint.py`: train-only opcode n-gram ranking and same-source compiler differentials.
- `service.py`: candidate search, recompilation oracle, confidence evidence.
- `api.py` / `worker.py`: bounded HTTP ingress and disposable resource-limited worker processes.
- `corpus.py`: metadata adapter, clone-group splits, microprograms, matrix and benchmark.

The search is bounded by elapsed time and 64 compilation attempts. Structured AST alternatives include preserving explicit constant pushes in mismatching methods, followed by typed method preservation and whole-assembly fallbacks. Each nonmatching structured/assembly candidate tries at most four ranked configurations; once an exact candidate is found, remaining configurations are tested within the same budget to report compatibility. Candidate compilation is keyed by compiler content identity and options, not merely the version label. Exactness compares **cell hashes**, not serialized BOC bytes.

## Research and evaluation

See [research/README.md](research/README.md), the pinned toolchain manifest, and generated JSON/text reports in `research/`. The 300 supplied bundles are grouped before splitting to reduce duplicate leakage. Holdout source is used only to produce benchmark inputs, never to reconstruct them or train ranking profiles. Compiler ranking weights are explicitly uncalibrated; ambiguous outputs cannot reveal their compiler's historical identity.

The source metadata includes historical compiler versions and expected code hashes, but no original BOCs. Evaluation records whether freshly compiled inputs match these expected hashes. A successful reconstruction of a freshly compiled input is not automatically a successful reconstruction of the originally deployed contract.

## Deployment and limits

Each HTTP request runs in a separate process with CPU, address-space, open-file and output-file limits. Compiler invocations use argument arrays and temporary working directories. Four worker slots bound concurrent load. The parent kills the request process group on deadline. Place the service behind your existing TLS/authentication/rate-limit proxy; run it under a dedicated unprivileged account with a read-only application/toolchain and a writable cache. Process resource limits are not a filesystem or network sandbox; use a container or equivalent OS isolation for hostile public workloads.

High-level reconstruction currently covers integer expressions, typed cell/builder/slice primitives, selected loops and branches, and nonrecursive method calls. General dictionary logic, recursive or dynamic signatures, and arbitrary continuation manipulation remain incomplete. Standard-dispatcher contracts can use explicit, hash-verified assembly preservation. Nonstandard dispatchers, exotic/levelled cells, and some native debug mnemonic formats remain unsupported; these return structured errors. This is an initial implementation, with limited high-level coverage rather than complete recovery of original FunC.

Standard-library lifting includes balance tuples, standard address parsing, message-address loads, coin loads/stores, dictionary serialization and lookups, null checks, message sending, and compound stack permutations. Generated stdlib output contains only required typed primitive declarations. Hybrid recovery preserves changed method bodies with their inferred signatures, retaining decoded callers, then verifies the whole contract again. The DNS NFT regression in `tests/data/stdlib_contract.b64` retains 14 of 15 methods as high-level FunC with an exact code hash; the large receiver still needs assembly preservation because its reconstructed stack allocation differs.

See [the stdlib pattern investigation](research/stdlib-patterns.md) for official DNS source comparisons, development-corpus prevalence, and reproducible checks.

BOC validation follows the official [TON serialization implementation](https://github.com/ton-blockchain/ton/blob/master/crypto/vm/boc.cpp); toolchains are pinned to immutable revisions in the lock manifest.

A hardened Linux deployment unit is provided in `deploy/tvm-decompiler.service`. Bootstrap the project under `/opt/tvm-decompiler`, then install that unit with systemd. It runs as a dynamic unprivileged user, keeps the installation read-only, writes cache only in `/var/lib/tvm-decompiler`, uses private temporary directories, limits memory/processes, and restricts networking to localhost. Put your reverse proxy in front of port 8080. The unit is a deployment configuration; the regression suite tests the application directly rather than starting a system service.

Confidence is measured, not a calibrated probability: exact cell hash gives 1.0; otherwise the score is `0.35 × instruction_match + 0.20 × cfg_match + 0.10 × cell_match`, capped naturally at 0.65. Partial scores of at least 0.55 are `medium`, lower scores are `low`. Instruction similarity averages opcode/operand/continuation unigram and bigram overlap; CFG similarity averages block and edge overlap; cell similarity compares payloads and reference topology. None of these partial metrics proves equivalence. `reconstruction_mode` distinguishes `structured`, mixed high-level/opaque `hybrid`, readable `assembly`, and opaque `cell_assembly`; `stack_analysis_complete` reports whether high-level lifting completed; `cfg_analysis_complete` separately reports unresolved dynamic control flow. Exact fallback confidence describes preserved bytecode, not recovered high-level source.

## Toolchains and adding a compiler

`toolchains.lock.json` pins ten compiler binaries/builds covering FunC 0.2.0, 0.3.0, and 0.4.0–0.4.6, including two distinct 0.4.4 release binaries. The matrix compares both identities; API version-family verification selects the newest installed pinned binary for that version. All experiments use one pinned official Fift/Asm/Disasm library bundle, isolating FunC changes. Historical assembler-library differences are not inferred.

To add a release, record its official asset URL, SHA-256, reported version, and compiler revision in the lock manifest. AppImages also require a hash for the extracted native executable. For a source build, pin the TON archive/revision and required submodule archives. Bootstrap records the actual resulting binary SHA-256 and local build environment in `build.json`; cache keys use that actual binary identity. Source builds are revision-reproducible but do not promise identical executable bytes across C++ toolchain versions. Run the regression suite, rebuild the matrix, and regenerate the fingerprints before evaluating the new version.

Operator environment variables: `TON_TOOLCHAIN_ROOT` selects the installed tools; `TON_CACHE_DIR` selects writable cache storage; `TON_CACHE_MAX_BYTES` bounds it (default 512 MiB, oldest writes evicted). HTTP clients cannot set these.

## Readability development cohort

[Lightweight-agent instructions](instructions/readable-corpus-agent.md) define the bounded GPT-5.6-luna medium task. The fixed development cohort, generated sources, and before/after measurements are in [research/readable-30](research/readable-30/REPORT.md). The initial baseline is Git commit `25f3aaa` (`init`).

The [70-contract expansion](research/readable-70/REPORT.md) freezes 70 additional clone groups, then measures the starting implementation, the lightweight-agent pass, and the assisted pass under the same search budget. [Expansion instructions](instructions/readable-70-agent.md) describe selection and validation. The report also includes a fresh regression run of the original 30 contracts; readable coverage and exact bytecode preservation are measured separately.

The [next 100 contracts](research/readable-100/REPORT.md) use 87 previously unused clone groups: 34 training contracts and 66 validation contracts, including 13 variants. [Task instructions](instructions/readable-100-agent.md) keep validation evaluation separate from training-driven fixes and leave holdout untouched.

Undecoded methods appear in the web readable view as opcode-first `fift { ... }` blocks, with nested continuations shown in full. The API exposes this mixed presentation as `display_contract` with `display_format: "func-fift-pseudocode"`. It is display syntax, not compilable FunC; `func`, `contract`, and their verification metrics continue to describe the underlying compilable source. The exact-bytecode view remains available.
