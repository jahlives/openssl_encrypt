# Task: Three Feature Additions to openssl_encrypt

## Project Context

This task adds three new capabilities to the `openssl_encrypt` project. The project has 
a plugin-based architecture for hardware tokens (HSM/CR), a chained KDF cascade 
(Argon2id, Balloon, scrypt, RandomX, etc.), a metadata-rich encrypted file format, and 
an established test suite of 1636+ tests. Work on a new feature branch off the current 
active development branch.

## CRITICAL: Approach and Mindset

This plan describes the INTENT of three features. It is NOT a strict specification of 
HOW to implement them. Before writing any code:

1. **Examine the actual codebase.** Read the relevant modules. Understand the existing 
   patterns for CLI argument parsing, metadata handling, KDF invocation, action 
   dispatch, and test structure. Do NOT assume conventions — verify them.

2. **Compare the requirements below against code reality.** If a requirement conflicts 
   with existing architecture, points to an inconsistency, or could be implemented 
   significantly better in a way the requirements don't anticipate, STOP and discuss 
   with the user before proceeding.

3. **Ask clarifying questions BEFORE starting.** Each feature below has implementation 
   ambiguities. Some are flagged explicitly; others you will discover by reading the 
   code. Compile a complete list of questions and ask them upfront, in one batch, 
   before writing any code.

4. **Never assume — always verify.** If you find yourself thinking "the project 
   probably does X this way," open the relevant file and check. Especially for: 
   metadata format, CLI parser style (argparse / click / custom), output formatting 
   conventions, error handling patterns, and plugin registration.

5. **Defer to existing patterns.** New code should look like it belongs in this codebase. 
   If you see a pattern used consistently for similar functionality, follow it. If 
   there's no clear pattern, ask which direction to go.

## Feature 1: Enhanced `info` Action — CLI Parameter Reconstruction

### Current State

The `info` action reads metadata from an encrypted file and displays it in a 
human-readable format.

### Goal

Extend the `info` action so that, in addition to the existing metadata display, it 
reconstructs and shows the CLI parameters (and their values) that would produce the same 
encryption settings as the file being inspected. This helps users understand exactly 
how a given file was encrypted, and lets them re-use the same parameters for a new 
encryption.

### Output Sketch (final format to be decided after reading existing `info` output)

```
[ existing metadata display ]

Reconstructed CLI parameters:
  openssl_encrypt encrypt \
    --kdf argon2id \
    --argon2-time-cost 4 \
    --argon2-memory-cost 2097152 \
    --argon2-parallelism 1 \
    --cipher aes-256-gcm \
    --pepper-source yubikey \
    ...
```

### Implementation Questions (must be resolved before coding)

- Does the metadata format store ALL CLI parameters explicitly, or are some derived/defaulted?
- Are there CLI parameters that have changed names or defaults across versions? If so, 
  how should reconstruction handle metadata written by older versions?
- Should the output be a copy-pasteable shell command, a structured table, or both?
- Should sensitive values (e.g., paths to keyfiles, hardware token slot numbers) be 
  redacted by default with an opt-in `--show-sensitive` flag?
- What happens if metadata contains parameters the current version no longer supports?

## Feature 2: Diceware Support for `generate-password`

### Current State

The `generate-password` command generates random passwords using character-based methods.

### Goal

Add Diceware-style passphrase generation as an alternative password generation mode.

### New CLI Parameters

- `--dice` — flag to activate Diceware mode (mutually exclusive with character-based 
  generation flags)
- `--dice-count N` — number of words in the passphrase (default: 10)
- `--dice-sep STR` — separator between words (default: empty string `""`)
- `--dice-list PATH` — path to a custom wordlist file (default: bundled EFF large 
  wordlist)

### Behavior

When `--dice` is provided, the tool selects `--dice-count` words uniformly at random 
from the wordlist, joins them with `--dice-sep`, and prints the result.

Randomness MUST come from a cryptographically secure source (e.g., `secrets.SystemRandom` 
in Python, or equivalent in the language used).

### Implementation Questions (must be resolved before coding)

- Where should the bundled EFF wordlist live in the package structure? (probably 
  `openssl_encrypt/data/eff_large_wordlist.txt` or similar — check existing convention)
- What is the expected format of a custom wordlist? (one word per line? EFF format with 
  dice-number prefixes? both supported?)
- Should the wordlist be validated (no duplicates, no whitespace in words, minimum 
  size for sufficient entropy)?
- Should the tool report the entropy of the generated passphrase (in bits)?
- How should `--dice` interact with existing `generate-password` flags? Strict 
  mutual-exclusion, or graceful precedence?
- Is the bundled EFF wordlist (7776 words, public domain) acceptable from a licensing 
  perspective for this project? Verify the project license is compatible.

## Feature 3: New `mangle-password` Action

### Goal

Add a new action `mangle-password` that takes a user-supplied password, runs it through 
the configured KDF cascade (the same cascade used for encryption), and outputs the 
derived password. No file is read or written. No encryption occurs.

### Use Case

The user wants to derive a strong, deterministic password from a memorable input plus 
the project's hardened KDF settings, then use the result as a password in third-party 
tools (password managers, disk encryption, encrypted archives, etc.).

### Interface Sketch

```bash
openssl_encrypt mangle-password \
    --kdf argon2id \
    --argon2-time-cost 4 \
    --argon2-memory-cost 2097152 \
    [other KDF params] \
    --output-format hex \
    --output-length 32

# Prompts for password (no echo)
Password: ********

# Outputs derived value
6f3a8b9c2d1e4f5a8b7c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
```

### Implementation Questions (must be resolved before coding)

- Should this action accept ALL KDF parameters that `encrypt` accepts, or a curated 
  subset? (If curated, which ones and why?)
- Should the salt be user-provided, derived from a fixed value, or random?
  **Critical:** if the salt is random, the output is non-reproducible — which defeats the 
  use case of "use this password elsewhere." If the salt is fixed, what is the source 
  of the fixed value? User-provided? Derived from a context string?
- Output formats: hex, base64, raw bytes (binary), word-based (Diceware-style mapping), 
  or all of the above with `--output-format` selector?
- Output length: full KDF output, or truncatable via `--output-length`?
- Should the pepper (hardware token CR) integration also be available here? Probably 
  yes — the whole point is "use my KDF cascade including the hardware token."
- How is the password input obtained? Stdin (with no-echo), prompt, environment 
  variable, file? Match existing conventions for `encrypt`.
- Should there be a `--confirm` flag to ask for the password twice (preventing typos 
  that would cause irreproducible output)?
- Security: the derived password will be displayed on the terminal. Should there be a 
  warning about shell history, clipboard, screen-sharing? Should the output be piped 
  to stdout only (no logging) by default?
- What happens if the user re-runs the same command with the same inputs — does it 
  produce identical output? (This is the deterministic property the use case requires.)

## Strict TDD Mandate

Every feature follows red-green-refactor:

1. Write a failing test that specifies the behavior
2. Run the test, verify it fails for the right reason
3. Write the minimum code to make the test pass
4. Run the test, verify it passes
5. Refactor only with all tests still green
6. Commit at this green state

Hardware-dependent tests (for `mangle-password` with hardware pepper) use 
`pytest.mark.hardware` and are skipped by default.

Use property-based testing (`hypothesis`) where appropriate:
- For Diceware: any valid wordlist + any seed should produce reproducible output
- For mangle-password: identical inputs MUST produce identical outputs (determinism test)
- For info reconstruction: round-trip property — encrypting with parameters X, then 
  reading metadata back, then reconstructing parameters, should yield X

## Commit Policy — Strictly Enforced

Commit after every relevant change. A "relevant change" is one red-green-refactor cycle 
OR a discrete refactoring step that leaves the codebase consistent.

### Mandatory Pre-Commit Verification

**NO COMMIT may be created unless ALL of the following conditions are met:**

1. All tests relevant to the changed code MUST pass. "Relevant tests" includes:
   - Every test in the same module as the changed file
   - Every test that imports the changed module (transitively)
   - The full test suite of the affected package
   - For changes touching shared infrastructure: the entire project test suite

2. The execution must be verified — not assumed. Run `pytest <relevant-path>` and 
   observe the actual green status in the output. Do NOT commit based on the assumption 
   that tests will pass.

3. **Before any commit that completes a feature (Feature 1, 2, or 3):** run the FULL 
   test suite at the repository root (`pytest`) and confirm all existing tests plus all 
   new tests pass. A feature is not "done" until the full suite is green.

4. Linter and type checker must pass on changed files. Run the project's standard 
   `ruff check` and `mypy` (or whatever the project uses — verify first) and ensure 
   clean output.

5. Commit message format:

```
   <type>(<scope>): <short description>

   - Adds test: test_<name>
   - Affects: <module-or-feature>

   Tests verified: <command-used>, <result>
```

### Forbidden Commit Patterns

- ❌ Committing without running tests
- ❌ Committing with a failing test (red commits are not allowed)
- ❌ Committing with `pytest -x`, `--no-cov`, or other shortcuts that skip relevant tests
- ❌ Committing with `git commit --no-verify`
- ❌ Squashing or amending commits to hide a broken intermediate state
- ❌ Marking tests as `@pytest.mark.skip` or `xfail` to make the suite green
- ❌ Bundling unrelated changes into one commit

### Feature Boundaries

Each of the three features must end with a clean commit titled with a clear feature 
marker, e.g.:

- `feat(info): complete CLI parameter reconstruction in info action`
- `feat(generate-password): complete Diceware passphrase support`
- `feat(mangle-password): complete mangle-password action`

These feature-boundary commits MUST be preceded by a full-suite test run. If the full 
suite fails, the feature is not complete — fix before claiming completion.

## Required Workflow

### Phase 0: Investigation (before any code)

1. Read the relevant existing modules:
   - The `info` action and its metadata handling
   - The `generate-password` command and its CLI parser
   - The action dispatch mechanism (how new actions are added)
   - The KDF cascade implementation (so `mangle-password` can reuse it)
   - The plugin system (in case hardware-pepper integration touches it)
   - The test structure for actions and commands

2. Compile a complete list of implementation questions based on what you find. Include:
   - All questions flagged in the feature descriptions above
   - Additional questions raised by your reading of the code
   - Suggested defaults / preferred answers where you have an opinion
   - Notes on any conflicts between this plan and the existing architecture

3. Present this list to the user and wait for answers before starting Phase 1.

### Phase 1–3: Implementation (one phase per feature)

For each feature:

1. Confirm with the user which feature to start (default order: Feature 1 → Feature 2 → 
   Feature 3, unless dependencies suggest otherwise).
2. Run the TDD cycle for each piece of the feature.
3. Commit each cycle individually.
4. At the end of the feature, run the full test suite. If green, create the 
   feature-boundary commit. If not, fix before claiming completion.
5. After every 5 commits, summarize progress so far and what remains.

### Phase 4: Documentation

Update:
- `README.md` with the new features
- Any existing usage docs that mention `info`, `generate-password`, or the action list
- `CHANGELOG.md` under the active version
- Help text / `--help` output for all new and modified commands

Documentation updates are part of the feature, not a separate task. The feature-boundary 
commit should not happen until docs are also updated.

## Constraints

- Python 3.10+ (verify the project's actual minimum supported version first)
- No breaking changes to existing public CLI or library API
- New optional dependencies (e.g., for Diceware wordlist handling) must be justified — 
  prefer using existing dependencies or the standard library where possible
- Bundled wordlist must be public domain or compatibly licensed; the EFF large wordlist 
  is public domain
- All new code must be type-annotated to the project's existing standard

## Success Criteria

- [ ] All three features implemented and documented
- [ ] All existing tests pass
- [ ] New tests cover all three features
- [ ] Property-based tests verify the key invariants (Diceware reproducibility, 
      mangle-password determinism, info round-trip)
- [ ] CLI `--help` output is complete and accurate for all new and changed commands
- [ ] No new linter or type-checker warnings
- [ ] Documentation is updated and tested (every CLI example in docs actually works)
- [ ] Each feature has a clean feature-boundary commit with full-suite green
