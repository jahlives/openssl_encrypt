# Changelog

All notable changes to the openssl_encrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.9] - TBD

### Added

- **`generate-password --json`** (gitlab#187 / github#104): the desktop GUI
  has always appended `--json` and parsed stdout as a JSON object, but the
  flag existed on no branch or release tag and the handler had no JSON path
  at all — so GUI password generation, and the Password Generator screen
  built on it, never worked. This is a JSON *mode*, not just a flag: the
  handler now emits one document on stdout in both character and diceware
  mode, carrying the fields the GUI reads (`password`, `entropy_bits`,
  `mode`, plus `strength`/`length` or `word_count`).

  The password is the payload on stdout and never reaches stderr in this
  mode: stderr is merged by `2>&1`, lands in scrollback and in the GUI's
  persistent debug log — the same reasoning applied to `encrypt --random`
  (gitlab#152). The on-screen countdown display is skipped rather than
  duplicated, and the generated password is registered with the audit-log
  redactor, whose shape heuristic would not otherwise match it.
  `ensure_ascii` is pinned, as for the other JSON channels.

  The character-mode policy check *warns* rather than rejecting, unlike the
  diceware gate which exits. Human mode shows that warning beside the
  password, but a machine caller reads stderr only on a non-zero exit, so
  the document carries `policy_valid` and `policy_warnings` instead of the
  verdict being lost. JSON is deliberately not stricter than the human
  path.

- **Lint: every argv the desktop GUI builds must parse against the real CLI
  parser** (gitlab#186 / github#103). Four times the GUI has emitted CLI
  surface that does not exist — `identity import --data/--alias`
  (gitlab#164), `identity list --json` (gitlab#183), `identity delete
  --contact` (gitlab#185), `generate-password --json` (gitlab#187) — each
  failing at argparse with exit 2 and each swallowed by the GUI into an
  empty result, so the feature simply never worked. Writing the widget does
  not verify the feature; only driving the real CLI does, and pytest never
  exercises the GUI.

  The lint reads `cli_service.dart`, extracts each call site's command path
  and flag literals, and checks them against the parser `build_subparser()`
  returns — the same object the CLI uses, not a reconstruction. (That
  required splitting the parser construction out of `create_subparser_main`,
  which built and immediately parsed `sys.argv`, so the surface it exposes
  could not be inspected.) Dart-interpolated literals are skipped rather
  than guessed at.

  Call sites that fail today are listed in a `KNOWN_BROKEN` registry, each
  naming its tracking issue, so the lint passes now but fails on anything
  new; companion tests assert that every entry is still genuinely broken and
  names an issue, so an exemption cannot outlive the bug it describes. It
  surfaced two more dead surfaces than the four already known: the GUI's
  pepper management and its keyserver/integrity connection tests call
  `plugin pepper`/`plugin keyserver`/`plugin integrity` subcommands that do
  not exist (gitlab#188) — `plugin` offers only `sign`, `trust-key` and
  `list-keys`.

  Review of the lint then found two more, in surface it had been blind to
  until its extractor was rewritten to cover the encrypt/decrypt paths:
  `--whirlpool-rounds`, which no subparser declares (gitlab#189), and
  `-a <algorithm>` in the steganography path, where `-a` is the short form
  of `--armor`, a boolean — so the cipher choice never reached the CLI and
  the command failed outright (gitlab#190). The latter is an *arity*
  defect, which a name-only model cannot see; the lint documents that gap
  rather than implying it covers it, as it documents that the
  command-preview builders are outside its anchor (gitlab#191).

- **Environment input path for the second password and the signer passphrase**
  (gitlab#154 / github#72, gitlab#159 / github#77): the keyed-hidden-mode
  second password and the `sign` signer-identity passphrase could be supplied
  only through a `getpass()` prompt, which reads `/dev/tty` — so neither the
  desktop GUI nor any CI caller could drive them at all, blocking GUI
  hidden-header support and the Sign screen. `OPENSSL_ENCRYPT_SECOND_PASSWORD`
  and `OPENSSL_ENCRYPT_SIGNER_PASSPHRASE` now carry them.

  Rather than a third and fourth private copy of the mechanism, the
  read-once-and-delete channel built for recovery slots (gitlab#144) is
  generalized into `modules/credential_env.py` and shared. Each variable is
  read once and removed from the environment immediately — including when a
  higher-priority source supersedes it — so it is not inherited by a later
  child process (several call sites run `subprocess.run()` with no `env=`); it
  is registered for audit-log redaction *before* the deletion, since in
  between it would match neither the live-environment check nor the
  fingerprint registry; a blank value is refused rather than falling through
  to a prompt a GUI subprocess could never answer; and the value is validated
  without being modified, so a credential set through one channel still opens
  through another.

  Neither variable can *enable* the feature it belongs to. This matters most
  for the second password: a non-`None` value there is what switches keyed
  hidden mode on, so a bare exported variable would otherwise write every file
  with a keyed hidden header the user never chose and cannot reproduce —
  readable by whoever planted it, and locking the user out of their own
  metadata. `--hidden-header` (or an explicit `--second-password*` form) must
  request the credential before the variable is read, and an HSM-only signer
  identity is never given a passphrase merely because a variable is set. The
  environment supplies a value; an explicit flag still selects the path.

  On the new environment channel a value containing a newline is refused
  rather than silently trimmed: the file-descriptor and prompt channels both
  stop at the first newline, so a trailing `\n` — exactly what passing a GUI
  text field's contents produces — would otherwise derive a different key from
  the same passphrase typed at the prompt, with no error at any point. The
  pre-existing `--second-password` flag deliberately keeps its exact byte
  semantics, so a file already encrypted with a newline-bearing value stays
  decryptable. `--second-password ""` now errors like a blank variable instead
  of falling through to a silently keyless header.
  `sign` with no passphrase and no terminal exits with an instruction naming
  the variable instead of a `getpass` traceback, and Ctrl-C at the prompt exits
  130 rather than being reported as a missing terminal. `encrypt --sign-with`
  uses the same variable and the same error handling — it signs with the same
  identity and was equally undriveable without a terminal.

  A variable that is set but not requested is now reported as a warning naming
  the variable (never its value) rather than dropped in silence: the help text
  points callers at it, so setting it and receiving a plain legacy-format file
  with cleartext metadata, at exit code 0 with no output, would be the worst
  possible outcome. `--second-password-fd` gained the same blank check as the
  other channels — an empty or EOF-closed descriptor previously yielded a
  silently *keyless* header for a caller who asked for a keyed one. Blank
  values are refused when encrypting but accepted when decrypting, so a file
  written by an earlier release with a whitespace-only value stays
  decryptable.
- **Desktop GUI: Verify Signature screen** (gitlab#158 / github#76): a new
  Pro-mode screen checks a detached signature against a file. Verification needs
  no password — it uses public keys, and trust comes from the local identity
  store, which refuses an unknown signer outright rather than reporting the file
  as merely unverified.

  The screen is built around not being misread. Three outcomes are kept
  visually distinct: a valid signature, an invalid one, and a check that could
  not be performed — the last shown as explicitly not a verdict. Naming an
  expected signer that the signature does not match is treated as a hard
  failure rather than an inability to check, since that is the strongest
  negative result available and it only arises when the user asked for it. A
  failed verification never attributes the file to a named person; it reports
  the claimed signer as unverified. Each algorithm component is listed so a
  failing one is not hidden by a passing one, with the caveat that component
  names come from the signature file and are not themselves signed
  (gitlab#160). The overall verdict is re-derived from the individual fields
  rather than trusted, so a truncated or inconsistent result cannot render as
  valid.

- **Desktop GUI: Batch Operations tab parity** (gitlab#155 / github#73): the
  Batch tab gains the HSM/YubiKey, remote-pepper and hash/KDF-chain controls the
  single-file Encrypt tab already had, and now sends them. Previously it passed
  no hash or KDF configuration and omitted HSM and pepper entirely, so batching
  silently used CLI defaults while the same files encrypted one at a time used
  whatever the user had configured — with nothing in the UI to show the
  difference.

  The hash and KDF panels were extracted from the Encrypt tab into a shared
  widget rather than duplicated, so the two surfaces cannot drift apart again.
  As on the Encrypt tab, that configuration is sent for symmetric encryption
  only: supplying it in asymmetric or cascade mode would take the CLI out of the
  branch that applies its built-in security template, and the panel is hidden in
  those modes so the interface never implies a setting applies where it is not
  sent.

- **Desktop GUI: Encrypt tab PQC key file and key-derivation controls**
  (gitlab#153 / github#71): the Encrypt tab's Advanced Options gain a field to
  load an existing post-quantum key file, an off-by-default switch for the
  legacy sequential key derivation, and a parallel key-derivation option with a
  worker count.

  The legacy switch is labelled as the downgrade it is: it pins the older
  format version 13, whose derived key is only as strong as the weakest step in
  the chain, which funnels wide-key ciphers through a narrower intermediate and
  omits the newer transcript binding. It is never the default.

  Three flags that plan items P16/P17 called for were deliberately **not**
  exposed, because on the GUI's code path they do nothing: `--keyring-store`
  and `--keyring-load` are gated on the `-p` value and the GUI passes the
  password through the environment, so the store never runs and prints nothing
  (gitlab#156) — offering it would invite a user to discard the only copy of a
  password that was never saved; and `--pqc-store-key` is already emitted
  unconditionally for every post-quantum algorithm, so a toggle could not turn
  it off (gitlab#157). Saving a new PQC key file is likewise unreachable
  without `--pqc-gen-key`, so the field loads only.

- **Desktop GUI: securely delete the source file after encrypting**
  (gitlab#151 / github#69): the Encrypt tab's Advanced Options gain an
  off-by-default switch that overwrites and deletes the original file once the
  encrypted copy has been written, with a selectable pass count. Every run is
  gated behind a confirmation naming the file and stating that the encrypted
  copy and its password become the only way back to the data.

  Implemented as a separate `shred` invocation after a successful encryption
  rather than by passing the CLI's own `--shred`: the GUI encrypts file-mode
  input by reading its text and passing it through a temporary file, so
  `--shred` would have wiped that temporary file instead of the user's source.
  The shred only runs once the encrypted output is confirmed written, never on
  a path where the encryption or the save failed.

- **Desktop GUI: Recovery Slots screen** (gitlab#145 / github#63): a new
  Pro-mode "Recovery" screen lists an envelope file's recovery slots, adds a
  generated recovery code or a recovery passphrase, removes a slot, and
  decrypts a file with a recovery credential when the password is unavailable.
  Every credential travels through the environment rather than the command
  line, and a generated code is written by the CLI to a private temporary file,
  shown once with copy-to-clipboard, and deleted — it is never placed on a
  stream or held in widget state. Removing a slot is gated behind an explicit
  confirmation naming the slot, since it irreversibly revokes that recovery
  path.

  Two GUI-side leaks found while building it are fixed with it: `CLIService`
  now defaults to **not** logging a command's stdout (it carries decrypted
  plaintext and generated credentials, so logging is opted into per call rather
  than opted out of), and the encrypt/decrypt error paths no longer write
  stdout to the debug log or embed it in the exception message — an error is
  precisely when stdout may hold a partially written secret.

- **`--json` output for the recovery-slot commands** (gitlab#146 / github#64):
  `list-recovery`, `recover`, `add-recovery` and `remove-recovery` gain a
  `--json` flag that emits a single JSON document on stdout *instead of* the
  human report, which otherwise goes to stderr as before. `list-recovery --json`
  reports every slot's `id`, `type` and full `key_id` (the human view truncates
  it to 16 characters for display; the value is bounded, since it comes from an
  untrusted file header). `add-recovery --json` reports the output path, the
  slot type, and which credential produced the slot — so a slot wrapped under a
  planted `$OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE` is distinguishable from one
  the user typed. Previously the only way to read a slot list or a generated
  code was to scrape an unversioned human-readable stderr format.

  A generated recovery code is **never** written to stdout or stderr in JSON
  mode. It unwraps the file's key, so it is password-equivalent, and neither
  stream is safe for it: stdout is the conventional target of `> file` (created
  at the caller's umask) and is merged into stderr by `2>&1`, while stderr
  reaches terminal scrollback and log files. Instead, `--recovery-code-out PATH`
  has the tool write the code itself to a file it creates `0600` and refuses to
  overwrite, and the JSON carries only that path; `--add-code --json` without a
  destination is refused rather than silently withholding the credential. The
  code is written *before* the envelope is modified, so the credential cannot be
  lost to a failed write; if the slot write then fails, the code file is left
  in place and reported rather than deleted, since a failure does not prove the
  slot was not written and an orphan code opens nothing. Prerequisite for the
  desktop GUI Recovery Slots screen.

- **Recovery credentials can be supplied through the environment**
  (gitlab#144 / github#62): the recovery-slot commands previously accepted a
  recovery code only on the command line — where it is visible in the process
  list, and unlike `--password`/`--rekey-password` with no warning — while
  recovery passphrases were reachable only through a `getpass()` prompt that
  reads `/dev/tty`, so no non-interactive caller could drive them at all.
  Three env vars now carry these credentials: `OPENSSL_ENCRYPT_RECOVERY_CODE`
  and `OPENSSL_ENCRYPT_RECOVERY_PASSPHRASE` (to unlock, for `recover`,
  `add-recovery` and `remove-recovery`) and
  `OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE` (the new passphrase for
  `add-recovery --add-passphrase`). Each is read once and deleted from the
  environment immediately — including when an explicit flag supersedes it — so
  it is not on the process list and is not inherited by a later child process
  (several call sites run `subprocess.run()` with no `env=`). `$CRYPT_PASSWORD`
  is now consumed on the same paths, closing a hygiene gap where the
  higher-value primary password outlived the lower-value recovery credentials.
  An explicit flag still selects *which* credential is used — an environment
  variable alone can never select the passphrase path, so a planted variable
  cannot silently wrap a file's key under an attacker-chosen passphrase — and
  `add-recovery` now names the credential source it used. Passing
  `--recovery-code` on the command line warns that it is visible in the process
  list (not silenced by `--quiet`). A blank or whitespace-only recovery
  passphrase is now refused from **either** channel — previously two Enter
  presses at the interactive prompt would wrap the file's key under an empty
  passphrase, and since a recovery slot is an additional wrapping of the same
  key, such a slot lets anyone unwrap the file. A blank environment value fails
  fast rather than falling through to a prompt a GUI subprocess could never
  answer, and passphrases are validated without being modified, so a slot added
  through one channel always opens through the other. Redaction of these values
  in the security audit log survives their removal from the environment,
  matched by an HMAC fingerprint under an ephemeral per-process key (never a
  bare hash, which would be an offline guessing oracle) — the existing check
  resolves the live environment and would otherwise never fire.
  `OPENSSL_ENCRYPT_REKEY_PASSWORD` is added to that list too, which it
  previously was not — though its own consumption site does not yet register
  the value, so its redaction still stops once consumed. Note that `unsetenv()`
  does not scrub the exec-time copy visible in
  `/proc/self/environ`, so this converts a world-readable `cmdline` leak into a
  same-uid residual rather than eliminating it entirely. Prerequisite for the
  desktop GUI Recovery Slots screen.

- **Desktop GUI: Rekey screen** (gitlab#142 / github#60): a new Pro-mode
  "Rekey" screen re-encrypts an existing file with a new password (and
  optionally a new algorithm) via the CLI `rekey` command, writing a new output
  file and leaving the original untouched. The old password is passed via
  `CRYPT_PASSWORD` and the new via `OPENSSL_ENCRYPT_REKEY_PASSWORD` (both
  environment variables the CLI deletes after reading — never on the process
  list or a temp file). This iteration changes password/algorithm only; full
  KDF/hash reconfiguration during rekey is not yet exposed.

- **Desktop GUI: live password-strength meter** (gitlab#141 / github#59): the
  Encrypt tab's password field now shows a live strength indicator (bar,
  category, entropy in bits, and weakness warnings) driven by the CLI
  `check-password --json` command. The password is passed on stdin (never as an
  argument) and the check is debounced to avoid spawning a CLI process per
  keystroke. Placed on the Encrypt tab only — where a password is being chosen;
  the Decrypt tab (entering an existing password) and the Password Generator
  (which already reports entropy/strength) intentionally omit it.

- **Desktop GUI: Secure Shred screen** (gitlab#140 / github#58): a new
  Pro-mode "Secure Shred" screen securely overwrites and deletes files (and
  directories, with a recursive toggle) via the CLI `shred` command, with a
  selectable pass count. Every run is gated behind a mandatory
  irreversible-action confirmation dialog listing the exact targets, and the
  UI blocks shredding a directory unless "recursive" is enabled (avoiding the
  CLI's stdin-less interactive prompt).

- **Desktop GUI: Password Generator screen** (gitlab#139 / github#57): a new
  Pro-mode "Password Gen" screen generates passwords via the CLI
  `generate-password --json` command in both **character** mode (length +
  lowercase/uppercase/digits/special toggles) and **diceware** passphrase mode
  (word count, separator, optional custom wordlist, force-small-wordlist). The
  generated password is shown with its entropy/strength and can be copied to
  the clipboard. Requires the CLI `generate-password --json` support
  (gitlab#138).

- **Desktop GUI: asymmetric-decryption controls in the Decrypt tab**
  (gitlab#137 / github#55): the Flutter desktop GUI can now decrypt files
  encrypted to an identity. The Decrypt tab's Advanced Options (Pro mode) expose
  a **decryption-identity** selector (`--with-key`) and, once an identity is
  chosen, a **verify-signature-from** selector (`--verify-from`) and a
  **skip-signature-verification** checkbox (`--no-verify`). These map to
  CLI flags that were already wired into the GUI's CLI service but had no
  widget setting them, so they were previously unreachable. Skipping signature
  verification is off by default and requires an explicit opt-in behind a clear
  warning; identity lists are de-duplicated and empty names skipped so a
  duplicate/blank identity name can no longer crash the tab.

### Security

- **`--` defeated the keyserver-credential redaction, and could trigger a
  keyring deletion** (security review of gitlab#177). gitlab#177 made `--`
  a working spelling in the argv layer; two argv scanners had not learned
  about it.

  The `--debug` argv dump redacts the token *immediately after* the
  `keyserver set-token`/`login` positional. With `--` in between it redacted
  the separator and printed the credential verbatim — and `--` is precisely
  what a user must type when the token starts with `-`, which base64url
  tokens and JWT segments do. stderr reaches terminal scrollback, is merged
  by `2>&1`, and the desktop GUI keeps a persistent debug log. The
  separator is now skipped rather than consuming the redaction.

  Separately, `--keyring-remove` was a raw membership test over the whole of
  `sys.argv`, running before any parsing, so
  `crypt shred -- --keyring-remove important-label` **deleted that stored
  password** and exited 0 having shredded nothing — when what the user
  described was two files with those names. It is now honoured only in
  top-level option position (before any `--`, before the command), and the
  `--keyring-remove=LABEL` spelling works, which the old scan missed
  entirely.

  Neither is a regression against a released version: the positional
  redaction rule is itself new in 1.4.9 — 1.4.8 did not redact that token at
  all, which is the already-recorded gitlab#133–136 item — and `--` was not
  usable in this layer before gitlab#177.

- **`enable-plugin`/`disable-plugin` reported success and changed nothing**
  (gitlab#199): both set an in-memory flag on a registration object that
  defaults to enabled at construction. Nothing wrote it to disk and nothing
  read it back, and the CLI builds a fresh manager per invocation — so the
  process died with the only copy of that state:

  ```
  $ openssl-encrypt disable-plugin --plugin-id steganography
  ✅ Plugin steganography disabled successfully
  $ openssl-encrypt list-plugins | grep -i stegano
  🟢 Enabled Steganography (v1.0.0)
  ```

  This is worse than a missing feature: a user who disables a plugin *for a
  security reason* got an unambiguous success message while the plugin
  loaded and ran enabled on the very next command — a false assurance about
  a control they believed they had applied.

  The state is now persisted through the plugin config and read back at
  load time, and a plugin recorded as disabled is registered but **not
  initialized** — `initialize()` is where a plugin claims resources and
  installs hooks — and not dispatched. It stays listed, as disabled, so it
  can be turned back on. If the state cannot be written, the command now
  reports failure instead of falling back to the flag that caused this.

  Residual, stated rather than papered over: a disabled plugin is still
  discovered and imported, so its module-level code runs. Refusing the
  import needs a file-to-id map that does not exist before the module is
  loaded.

  Reachable only from 1.4.9 (gitlab#179), so no released version is
  affected and no advisory is warranted.

- **`create-usb` overwrote root autorun files and wrote drive secrets at
  the default umask** (gitlab#207): `_is_removable_drive` only ever logged a
  warning, so a mistyped `--usb-path` went ahead — creating a portable
  installation in, say, the home directory and **overwriting** any
  `autorun.inf`, `autorun.sh` or `.autorun` already there, with no existence
  check at all. Those are now refused unless `--yes` is given, and a target
  that does not look removable requires confirmation (or `--yes`
  non-interactively) before anything is written.

  Nothing on this path was `chmod`'d except the three files deliberately
  made 0755, so the per-drive salt, the integrity manifest and the portable
  config were created at the process umask — typically 0644. They are now
  owner-only where the filesystem supports it, best-effort so that a FAT32
  target (where modes are meaningless) does not fail the whole operation.

  The confirmation lives at the CLI layer rather than in the library
  function: one that prompts is unusable from a script.

- **The helper written onto the drive could not run** (gitlab#206):
  `create-usb` writes a standalone `crypt.py` to the drive, chmods it 0755,
  and points the workspace README and the Windows batch files at it — and
  its template carried a package-relative import (`from ..crypt_utils
  import eprint`), which in a standalone script fails immediately with
  `ImportError: attempted relative import with no known parent package`. It
  now has a local `eprint` and runs.

  Two more defects from the same generator: the Windows batch files were
  written from a non-raw string containing `\n`, so each was a single
  unusable line with a literal escape; and the generated help told users to
  pass the master password as `--password mypass`, putting it in the
  process list and shell history. The batch files no longer take a password
  argument at all, and the help now points at the prompt or
  `CRYPT_PASSWORD`, with the reason stated. Guidance written *by* the
  security tool onto the medium carries more weight than a user's own
  habit, which is why this counted as more than a docs nit.

  Finally, `--executable-path` and `--keystore-to-include` silently skipped
  a path that did not exist, recording `included: False` while the CLI
  summary just omitted the line — so a typo left the user believing their
  keystore was on the drive. Both are now checked up front and refused.

- **A new USB drive got the weakest key derivation in the tool, and
  `--pbkdf2-iterations` was silently ignored** (gitlab#205): every round
  option defaults to 0, so a plain `create-usb --usb-path X` passed no
  config and derived with PBKDF2-HMAC-SHA256 at 100 000 iterations — what
  this codebase's own comment calls "below the OWASP floor" — to protect an
  encrypted keystore and integrity manifest on removable media, the
  artifact with the highest offline-attack exposure the tool writes.
  Argon2, scrypt and Balloon are not wired into this path at all.

  Separately, `multi_hash_password` never reads `pbkdf2_iterations`: 100k
  and 5M derive the *identical* key. The value was still written into
  `hash_config.json` and `.integrity`, so the drive advertised a work
  factor that had never been applied. That option is now refused with a
  pointer to the round options that do work, rather than recorded as a
  control that was not applied.

  A drive created with no explicit rounds now **records** a strong config
  instead of falling through to the weak default. Expressed as hash rounds
  rather than a raised PBKDF2 count deliberately: the fallback's iteration
  count is recorded nowhere a verifier can read — the drive's
  `security_profile` lives inside `.integrity`, which is encrypted with the
  key derived from that profile — so raising it would derive a different
  key, fail to decrypt, and report a good drive as **tampered**. Rounds are
  stored on the drive and read back on verify, so new drives carry their
  own parameters and the no-config path stays byte-identical for drives
  that already exist.

- **`create-usb` could be tricked into overwriting an arbitrary file**
  (gitlab#204): the hash-manifest encryption wrote to a path built by
  string concatenation — `temp_input_path + ".enc"`. The *input* was a
  claimed 0600 temporary file, but the output was an unclaimed sibling in
  the shared temp directory whose name anyone able to list it could derive,
  and `encrypt_file` defaults to `secure_mode=False`, so no `O_NOFOLLOW`
  was applied. A local attacker who pre-planted that name as a symlink got
  an arbitrary file overwrite as the invoking user — demonstrated, with the
  victim file replaced by ciphertext — and the subsequent permission fix-up
  then chmod'd the symlink target.

  Both temporary paths are now claimed by their own `mkstemp`, and the
  encryption runs with `secure_mode=True` so a symlink at the output path
  is refused at the OS level instead of followed.

- **`create-usb` copied private keys onto the drive** (gitlab#203): the
  project copy used `shutil.copytree` with no filter and the default
  `symlinks=False`, so run from a source checkout — which the project-root
  walk explicitly targets — it copied the whole tree. Against this checkout
  that was **4 test identity private keys** (`*_private.pem` under
  `unittests/testfiles/`) and 23 MB, landing unencrypted on a drive that is
  by design carried around, typically on FAT32 where the preserved mode
  bits mean nothing. They are test fixtures rather than production secrets,
  but the same path would copy a real key a user had placed in the tree.

  Key material (`*.pem`, `*.key`, `*.pqc`), the test tree and build caches
  are now excluded, matched by name at every depth — a key does not become
  safe to ship by sitting a directory deeper — and symlinks are copied as
  links instead of being dereferenced, which was a second way for content
  outside the copied subtree to end up on the drive. The copy is 5 MB and
  the tool itself is unchanged.

- **A planted named pipe hung `verify-usb` forever** (gitlab#202):
  `_sha256_file` claimed in its own docstring that its byte bound stopped "a
  FIFO / symlink to an unbounded stream ... from looping forever". It did
  not — the bound applies to the read, but `open()` on a FIFO blocks inside
  `open()` itself, before a byte is read. The added-file and autorun scans
  guarded with `is_file()`; the main manifest loop guarded with `exists()`,
  which is true for a FIFO. So replacing any manifest-listed file with a
  named pipe hung verification indefinitely — on the exact command whose
  job is to tell you the drive was tampered with.

  Files are now opened `O_NOFOLLOW | O_NONBLOCK` and required to be regular,
  and a listed name that is no longer a regular file is reported as
  **tampering** rather than hashed. That is the correct verdict: a real
  manifest lists regular files, so anything else at that path is a
  substitution. `O_NOFOLLOW` also stops a listed name replaced by a symlink
  from causing a file outside the drive to be read.

- **The portable-USB drive key was never actually wiped** (gitlab#201):
  every `secure_memzero` call on that path was a no-op whose return value
  was discarded. `PBKDF2HMAC.derive()`, `multi_hash_password` and the
  length-normalising `sha256(...).digest()` all return immutable `bytes`,
  and `secure_memzero` refuses immutable input and returns `False` without
  touching the caller's buffer — the documented M10 contract. So the
  AES-256 key protecting an encrypted keystore and the integrity manifest
  *on removable media* stayed resident for the process lifetime while the
  code read as though it had been wiped.

  The derived key is now held in a `bytearray` from creation, so the
  existing wipes take effect. Derived values are byte-identical — pinned by
  a test against a known PBKDF2 vector — so existing drives verify
  unchanged.

  `verify_usb_integrity` also wiped on the success path only: a bare
  `except: raise` with no `finally`, so the overwhelmingly common outcome —
  a wrong password, or an actually tampered drive — left both the key and
  the password resident. That and the equivalent gap in
  `_read_hash_config_from_integrity` are now `try/finally`, matching
  `create_portable_usb`, which already had it.

- **`verify-usb` took its key-derivation cost from the drive it was
  checking** (gitlab#200): `verify-usb` is the command you run *because you
  do not trust the drive*, and with no `--sha*-rounds` flags it read
  `config/hash_config.json` — plaintext, unauthenticated, sitting on that
  same drive — and fed it straight to the KDF before any integrity check
  ran. Measured before the fix, the attacker set the work factor linearly:
  `{"sha512": 1}` derived in 0.02 s, `1000000` in 2.48 s, so `10**12`
  extrapolates to roughly 29 days; an Argon2 or scrypt block with a large
  `memory_cost`/`N` exhausts memory instead, and the uncapped `json.load`
  OOM'd on a planted multi-GB file before parsing finished.

  The read is now capped and the document validated against an allowlist of
  exactly what `create-usb` writes — the flat hash-round keys, the PBKDF2
  iteration count, and the `type` key — with integer values in range. An
  allowlist rather than a per-key ceiling because the file carries no
  authentication at all: there is no reason to honour a shape the writer
  never produces, which is what refuses the memory-hard blocks by shape. A
  rejected file falls back to the built-in derivation exactly as a missing
  one does, so a real drive still verifies.

  Reachable only from 1.4.9: `verify-usb` exits 2 with `invalid choice` in
  every release up to 1.4.8 (gitlab#179), so no released version is
  affected and no advisory is warranted.

### Fixed

- **Combined short options, abbreviated long options and a leading `--`
  broke command routing** (security review of gitlab#177). The command scan
  classified each leading option as boolean or value-taking by exact
  membership, which cannot express two forms argparse accepts — so the
  command was read as somebody else's value and the invocation failed:

  ```
  crypt -qy install-dependencies    ->  invalid choice: 'install-dependencies'
  crypt -q -y install-dependencies  ->  works
  crypt --deb identity list         ->  invalid choice: 'identity'
  crypt --debug identity list       ->  works
  ```

  `-qy` is the natural spelling for the one command `--yes` exists for, and
  no parser here sets `allow_abbrev=False`, so `--deb` is a valid prefix.
  Bundled short options are now boolean only if every letter is, and long
  options resolve by unambiguous prefix; unknown or ambiguous still means
  "takes a value", the fail-closed direction that stopped `--alias
  telemetry` being read as a command.

  A leading `--` went the other way: `crypt -- identity list` found no
  command and routed to the wrong parser. POSIX reads that as "identity is
  a positional" — but argparse does **not** strip the separator before a
  subparser, it reports `invalid choice: '--'`, so finding the command was
  not enough and a leading separator is now removed. (The review's premise
  that argparse strips it does not hold; verified directly.) A separator
  *after* the command is still preserved, which is what gitlab#177 fixed.

  Also fixes the hardcoded fallback used when the parser cannot be built:
  it listed `--kdf-workers` as boolean, so on that path it would not consume
  its value and the scan would read `4` as the command — verbatim the
  gitlab#171 bug. It now excludes the value-carrying flags.

- **`install-dependencies --yes` was rejected** (gitlab#176): `--yes`/`-y`
  is declared on the top-level parser with the help text "Automatic yes to
  prompts (for install-dependencies command)" and was recognised by the
  routing scan — but it was never *relocated*, and the
  `install-dependencies` subparser declares no arguments at all, so the one
  invocation the flag exists for exited 2 with
  `unrecognized arguments: --yes`.

  It was held back from gitlab#171 because `hsm fido2-unregister` declares
  its own `--yes`, and argparse copies a subcommand's whole namespace back
  over the parent's, so that subparser's `False` default would silently
  overwrite a relocated one. That declaration now uses
  `default=argparse.SUPPRESS` — the same treatment `--quiet` needed — and
  `--yes` joins the relocatable set. Both directions are pinned: a relocated
  `--yes` survives that subcommand, and not passing it still leaves it
  false.

  The other half of this issue — `main()`'s routing skip-set being a
  hand-maintained duplicate — was closed by gitlab#177's shared scan. The
  remaining list is now covered by a test asserting the monolithic parser's
  command `choices` are all known commands, which immediately found `info`
  missing from that list. Harmless today (it routes to the flat parser,
  which accepts global flags anywhere) but latent: a subparser for `info`
  would have broken it the day it was added.

- **Global-flag relocation ignored `--` and could read an option value as
  the command** (gitlab#177): the preprocessing that lets `--debug` and
  friends work after a subcommand did not stop at a bare `--`, so a file
  literally named `--quiet` was hoisted out of its subcommand's arguments
  and read as a flag — in exactly the place a user reaches for `--` to stop
  that happening. And it looked for the command name anywhere, including
  option *values*: gitlab#171 widened the recognised set from 20 names to
  42, adding ordinary barewords (`test`, `version`, `sign`, `recover`,
  `template`, `identity`, `plugin`, `hsm`, `armor`), so
  `--alias telemetry` opened the relocation gate on a command line with no
  subcommand at all.

  Impact was low rather than nil — relocation moves only exact global-flag
  tokens and preserves relative order, so no positional was ever read as a
  password — but the behaviour was unpredictable in the two places users
  reach for predictability.

  Both scans now stop at `--` and skip an option's value. They are also now
  the *same* scan: `main()`'s routing decision was a third hand-maintained
  copy of "which flags carry a value", and it had already drifted twice.
  Which options take a value is read off the real parser rather than
  listed, and both the value-taking and boolean sets are needed — `--yes`
  and `-h` are top-level booleans that are deliberately not relocatable, so
  keying off the relocatable set alone made `crypt --yes encrypt` swallow
  the command.

- **Seven documented commands could not be run** (gitlab#179 / github#94):
  `create-usb`, `verify-usb`, `list-plugins`, `plugin-info`,
  `enable-plugin`, `disable-plugin` and `reload-plugin` were listed in
  `--help`, documented, declared by the parser and backed by working
  handlers — and every one of them exited 2 with
  `argument command: invalid choice`. They were named in the list that
  decides which commands go to the subparser, no subparser had ever been
  registered for them, and nothing connected those two claims. The
  plugin-management surface was unreachable from the CLI as a result.

  The list answered two different questions at once: "is this token the
  command, so the flags after it belong to it" (true of every command,
  whichever parser handles it) and "which parser handles it" (true only of
  the 35 with a registered subparser). Those are now separate:
  `KNOWN_COMMANDS` keeps the first, and the routing set is read off the
  built subparser rather than maintained beside it, so a command with no
  subparser falls through to the monolithic parser that declares it. A
  routed-but-unregistered command is no longer representable, which is the
  point — the same drift produced gitlab#171 in the same file.

  Verified equivalent for everything that already worked: the derived set
  differs from the old list by exactly these seven and nothing else, and
  all 42 known commands now dispatch. `SUBPARSER_COMMANDS` remains as an
  alias.

- **A lint for GUI service surface with no caller** (gitlab#198 /
  github#116): the argv lint reads the argv `cli_service.dart` *builds* and
  checks it against the real argparse tree, catching a flag the GUI sends
  that the CLI cannot accept. This is the mirror image — surface the GUI
  declares and never sends, because no widget passes it. Both are "the
  plumbing exists, one end is missing", and both hide behind a green test
  run.

  It exists because the audit found `CHANGELOG` entries describing
  Encrypt-tab controls that do not exist: the service half of gitlab#153
  landed, the widget half did not, and nothing noticed. gitlab#141's
  password-strength meter is in the same state — `checkPassword()` is
  implemented and nothing calls it.

  Run against the current tree it finds **50 unwired parameters across 8
  methods**, including the whole steganography surface: `encryptWithStego­
  graphy`, `encryptTextWithSteganography` and `decryptFromSteganography` are
  declared with 35 parameters between them and **no widget calls any of
  them**, so that feature is unreachable from this GUI regardless of what the
  flags say. Each gap is registered in `KNOWN_UNWIRED` against the issue that
  tracks it, and a stale entry is an error — an exemption that outlives its
  gap stops the check protecting that surface.

- **Recovery passphrases are held to the password policy** (gitlab#149):
  `add-recovery` accepted a one-character recovery passphrase — the check
  added under gitlab#144 rejected only blank and whitespace-only values —
  while the primary password from `OPENSSL_ENCRYPT_PASSWORD` was policy-
  checked. A recovery slot is an *additional wrapping of the same file key*,
  so a file's confidentiality is that of its weakest slot, and Argon2id at
  t=3/64 MiB does not rescue a three-character secret. The weaker credential
  on the same key was getting the weaker check.

  Both channels — `$OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE` and the
  interactive prompt — now go through the same policy as a password, with
  `--force-password` to override and `--password-policy` to choose the level,
  matching the flags the rest of the tool uses. The desktop GUI can pass
  `--force-password` too; without that, its users would have been told to use
  a flag the app had no way to send.

  The refusal lists the actual reasons — too short, no uppercase, no digit —
  on stderr, unconditionally, because `ValidationError` is a `SecureError`
  whose message is otherwise replaced by a generic string. A first version
  printed a strength verdict instead and managed to say **STRONG** directly
  above the refusal, because that figure is raw search space while the gate
  is character classes; a refusal the user cannot understand is one they will
  bypass. The entropy number is gone entirely: it inverts to the exact
  distinct-character count and class set of a credential that unwraps the
  file key, on a stream that reaches scrollback and the GUI's debug log.

  `--password-policy none` is deliberately not offered on this subcommand. It
  would be a second, silent bypass beside `--force-password`, and because
  `main_with_args` back-fills that exact value for namespaces lacking the
  attribute, honouring it would turn the check into a no-op the day the flag
  is renamed — a fix that fails open with nothing to notice.

  **Unlocking is deliberately not policy-checked.** Enforcing there would
  refuse a passphrase the user already holds, on a file whose primary
  password is usually already gone — turning a weak-credential warning into
  permanent data loss. Slots created before this change, or with
  `--force-password`, still open; only creating a new one is gated. Blank
  stays refused on both paths, and `--force-password` does not reach it: a
  blank-passphrase slot is equivalent to publishing the file.

  Six existing tests used weak literals and now fail the policy; they were
  testing the add/recover mechanism, the environment channel and the
  variable-consumption rule, not password strength, so they use
  policy-passing values. The one that guards against silent normalisation
  keeps its surrounding whitespace — that padding *is* the property under
  test, and the policy does not touch it.

- **`rekey`/`decrypt` with `-o` equal to `-i` truncated the input**
  (gitlab#195 / github#112): the residual gitlab#148 left behind. That issue
  fixed the envelope header writer, but the slow paths still decided
  atomicity from a flag rather than from the filesystem — `rekey_file` used
  `in_place = output_file is None`, so naming the input as the output took
  the non-atomic branch and handed that path straight to `encrypt_file`,
  which opens it `"wb"`. `decrypt_file` had the same shape. Both truncated
  the user's only copy before the replacement existed, so a crash, a full
  disk or an exception in between left a shortened, unreadable file where the
  original had been.

  Both now derive the answer with `_write_destroys_input` — the same
  predicate the envelope writer uses, so there is no third definition of "the
  same file" to drift out of step, which is exactly how these two paths came
  to be missed. `decrypt -i f -o f` and `rekey -i f -o f` go through a temp
  file and `os.replace`; `/dev/stdout` and `/dev/stderr` still stream, since
  they are not files to replace and nothing of the user's is at risk there.

  The envelope writer's machinery is factored out as
  `_write_replacement_bytes`, so "replace a file's contents without
  destroying it" now has one implementation rather than one per caller. The
  asymmetric decrypt path is routed through it too, and gained the plaintext
  permission clamp it was missing — the atomic path inherits the *original*
  file's mode, and a `.enc` that arrived by scp or a git checkout is commonly
  0644, so `decrypt --with-key --overwrite` could leave world-readable
  plaintext.

  `encrypt -i f -o f` is covered as well, on the failure path only: a
  successful same-file encrypt was always fine (verified at 3 MB and at
  13.5 MB, above the streaming threshold), but an interrupted one destroyed
  the plaintext before the ciphertext existed. Refusing the command would
  have broken something that works.

  `rekey` asks two questions rather than one. Deriving only "does this write
  land on its own input" and then calling `os.replace` broke hard links:
  replace installs a *new* inode, so `rekey -i a -o b` on two names for one
  file gave `b` the new password and left `a` readable with the **old** one,
  while reporting "Rekey completed successfully" — a rotation that silently
  half-happened. It now also asks whether the target may be replaced at all,
  and writes through the shared inode when it may not.

  Both regression tests inject a disk-full failure at the layer the fixed
  path actually writes through, which took two attempts to get right: the
  first version patched `builtins.open`, which the atomic path never calls,
  so it passed while asserting that a *successful* same-file decrypt leaves
  the ciphertext unchanged — not the contract. Reverting either fix now fails
  the corresponding test.

- **`--gui` was unreachable via `python -m`, and started the legacy GUI**
  (gitlab#197 / github#115): two defects stacked on each other.

  `python -m openssl_encrypt --gui` failed with `the following arguments are
  required: action`. There were two entry points into the program and only
  one handled the flag: the console script is declared as
  `openssl_encrypt.cli:main`, which checks for `--gui`, but `__main__.py`
  imported `main` from `modules.crypt_cli` directly and so never saw it.
  `__main__.py` now routes through `cli.main`, and a test asserts the two
  cannot diverge again.

  Underneath that, `--gui` launched `crypt_gui.py` — the tkinter interface —
  while the current GUI is the Flutter desktop application under
  `desktop_gui/`, which had no entry point from the Python side at all.
  Fixing only the routing would have sent the flag to the wrong program more
  reliably.

  `--gui` now starts the desktop application, looking in a defined order: the
  `OPENSSL_ENCRYPT_GUI` override, the installed Flatpak
  (`com.opensslencrypt.OpenSSLEncrypt`), a built bundle in the source tree
  (release before debug), then a binary on `PATH`. If none is found it says
  so and names the ways to get one, rather than falling back to the legacy
  interface — silently starting a different program than the one asked for is
  the defect this fixes, so it is not the remedy for it either.

  The tkinter interface stays reachable as `--gui-legacy`; it needs no build
  step, which makes it useful where the desktop app cannot run.

  The Flutter toolchain is never invoked implicitly. `flutter run` compiles
  and executes code from the working tree, which is not something a `--gui`
  flag should do on the user's behalf, so it is only suggested in the
  not-found message. The launcher passes an argv list to `subprocess.run`
  with no shell, and the tests pin that.
- **`--pqc-keyfile`: a second implementation wrote the post-quantum private
  key in the clear, and the flag could never save** (gitlab#157):
  `crypt_cli.py` carried two independent copies of the keyfile save/load
  logic. `320305ee` added password-wrapping to the copy that existed then;
  `c41a3a1cb` ("fix for claude code massive deletions") reconstructed the
  file and reintroduced the pre-fix plaintext pattern as a second copy; and
  `aef4ab42` (gitlab#131/F16) later upgraded the wrapping to Argon2id, its
  own message describing "the one write site". The duplicate wrote
  `private_key` as bare base64 with no `key_encrypted` marker, and its loader
  read `private_key` unconditionally — so handed a properly wrapped keyfile
  it would have base64-decoded the AES-GCM ciphertext and used it as the key.
  The duplicate is deleted.

  Separately, `--pqc-keyfile` could not save through the documented
  `encrypt` subcommand: the save branch is gated on `--pqc-gen-key`, which was
  declared only on a vestigial monolithic parser inside `main_with_args`, so
  `encrypt --pqc-gen-key` exited 2 with `unrecognized arguments`. Naming a
  path that did not exist matched neither branch and raised nothing — the user
  got an ephemeral key, no file, and no way to open the ciphertext with the
  keyfile they believed they had made. (The legacy argument ordering, with an
  option before the subcommand, *did* reach the monolithic parser and save;
  that is how the cleartext writer above was reachable at all.)
  `--pqc-gen-key` is now declared on the `encrypt` subparser, naming a
  non-existent keyfile without it is refused with an instruction instead of
  ignored, and `--pqc-gen-key` without `--pqc-keyfile` — the mirror image, and
  newly reachable now that the flag exists — is refused too.

  The keyfile is also resolved **once**, before the overwrite branch, so both
  output paths use the same keypair. Deleting the duplicate without moving
  this left `--overwrite` with no keyfile handling at all: it encrypted with
  an ephemeral key and only reached the keyfile code afterwards, so an
  unreadable or missing keyfile was reported *after* the input had already
  been replaced. Caught in review; the input is now left untouched when the
  keyfile cannot be used.

  The keyfile is written through `create_secure_file(..., exclusive=True)`,
  so it is created 0600 rather than at the umask (typically 0644), a
  pre-planted symlink or FIFO at that path is refused rather than followed,
  and an existing file is never silently clobbered.

- **argv lint: a declared flag is not necessarily a correct flag**
  (gitlab#190): the lint checked that every flag the GUI sends exists on the
  target subcommand, but not that it can take the value placed after it.
  That is how gitlab#190 survived it — the GUI sends `-a <algorithm>`, and
  `-a` does exist, as the short form of `--armor`, a `store_true`. argparse
  sets `armor=True` and leaves the algorithm as an unrecognised positional,
  so the command exits 2 while every flag in it is "declared", and the
  user's cipher choice would silently have become "ASCII armor" had it
  parsed.

  The lint now checks arity too. Doing so required reading argv *elements*
  rather than string literals: the offending value is a Dart variable, not a
  quoted string, so a literal-only reader saw nothing after the flag at all
  and could not have found this no matter how the check was worded. The GUI
  call is corrected to `--algorithm`, so steganographic encryption works from
  the GUI for the first time.

  Commands that declare a positional are exempt, because a stray value is
  absorbed by it rather than rejected — `generate-password` is the live case,
  and it is also where this lint's flattening of `if`/`else` branches into one
  argv would otherwise have produced a false positive.
- **GUI command previews were not covered by the argv lint** (gitlab#191):
  the lint anchored on `_runCLICommand*(` call sites, so it checked every
  argv the GUI *executes* but neither of the two builders that construct a
  full command line and render it to the user as copy-pasteable text. Same
  defect surface — a preview that fails at argparse if pasted — and they
  build `args` the same way, so only the anchor had to widen; a missing
  builder is now a hard error rather than silent lost coverage.

  On this line the previews were already flag-clean — `--whirlpool-rounds`
  went with gitlab#189 — so widening the anchor added coverage without
  finding a defect here. It found one on 1.5.x.
- **GUI identity deletion sent `--contact`, a flag that never existed**
  (gitlab#185): `identity delete <name> --contact` exited 2 at argparse, so
  GUI contact deletion had never worked, and with no `--force` the CLI's
  confirmation `input()` raised EOFError on a non-tty pipe. It now sends
  `--kind own|contact` — the flag gitlab#173 added for exactly this choice —
  and `--force`, since the app runs its own confirmation dialogue.

  Getting this wrong is not cosmetic: deleting *both* entries destroys the
  own identity's private keys, making every file encrypted to it unreadable,
  and drops the contact's TOFU pin so a later import of that name is
  accepted as first use with no key-change warning.
- **`keyserver show-token` no longer prints part of the bearer token**
  (gitlab#178): the handler revealed the first 8 and last 4 characters with a
  plain `eprint`, bypassing the `debug_secret()` chokepoint every other
  secret in this codebase goes through. Twelve characters of a bearer token
  is still key material, and stderr is not a private channel — it reaches
  terminal scrollback, is merged by `2>&1`, and the desktop GUI keeps a
  persistent debug log.

  The command keeps its job: it reports whether a token is configured, in
  the standard redacted form (byte length plus a per-process keyed
  fingerprint), and names the token file. Reading the value back
  deliberately now goes through the same explicit `--debug
  --unsafe-show-secrets` opt-in as every other secret, instead of a private
  masking rule of its own. Rotate any token whose prefix may have been
  captured in a log.
- **Recovery-slot rewrites cannot destroy the ciphertext they manage**
  (gitlab#148): the envelope writer has an atomic path (temp file in the
  same directory, fsync, `os.replace`, mode preserved) and a truncating one
  that opens the destination `"wb"`. A crash or ENOSPC part-way through the
  truncating path leaves a shortened, unreadable file and no copy of the
  original — and when the destination is the input, that is the user's only
  ciphertext. Recovery slots exist precisely so a file survives losing its
  password, so destroying it while managing them defeats the feature.

  The CLI already chose the atomic path for same-file rewrites; the writer
  now derives that choice itself, immediately before the write, and no
  longer trusts the caller's `in_place` flag — a caller that omits it (the
  documented Python API example did exactly that) cannot truncate a file in
  place, and a caller that asserts it cannot skip the exclusions below.
  `output_file=None`, the sibling API's "rewrite in place" convention, is
  honoured rather than raising.

  Three cases cannot use the atomic path, because `os.replace` installs a
  *new* inode and each of them depends on the existing one surviving: a
  symlink on either side (the link itself would be replaced), a file with
  more than one hard link (the other name would keep the old envelope — for
  `remove-recovery` a silent revocation failure reported as success), and
  anything that is not a regular file (a FIFO named as both input and
  output would be destroyed rather than written through). The hardlink
  exclusion reverses an earlier decision, for the same reason the symlink
  one was made.

  Being excluded from the atomic path does **not** mean being unprotected:
  those cases must be written *through* the existing inode, so the writer
  copies the original to an fsynced backup beside it first, restores it —
  also fsynced, before the backup is removed — if the write fails, and
  removes it on success. If the restore fails too, the backup is kept and
  its location is printed to stderr, because at that point it is the only
  copy of the file and it is dot-prefixed, so an `ls` would not show it. A
  crash leaves the backup on disk for manual recovery; if it cannot be
  removed afterwards, that is reported rather than passed over, since it is
  a copy of the file as it was *before* the change — for `remove-recovery`
  still openable by the credential just revoked, for `rekey` by the old
  password.

  A same-file rewrite of something that is *not* a regular file — a FIFO or
  a device node named as both input and output — is now refused rather than
  written: no backup of it can be taken, so it could not be made
  recoverable. Nothing legitimate reaches that case.

  A failure to *open* the destination — a read-only file in a writable
  directory, an immutable one, a read-only filesystem — truncated nothing,
  so it no longer runs the recovery handler. Otherwise a routine permission
  error was reported as `CRITICAL: … the original could not be restored`
  and left a full copy of the envelope behind, for a file that was never
  touched.

  This makes the two write-through commands O(file) rather than O(header)
  for a symlinked or multiply-linked envelope, and they need free space
  equal to the file; noted in `docs/OPEN_QUESTIONS.md`.

  The envelope rekey fast-path carried a second, weaker copy of this write
  logic (no fsync, no same-file check), so the guarantee applied to the
  recovery-slot commands only. It now delegates to the same writer, which
  is byte-for-byte equivalent, so both paths get the same protection.

  Regression tests simulate a genuine disk-full failure part-way through
  the write — earlier coverage only proved that failing *before* any byte
  was written was safe — on both the atomic and the write-through paths,
  and assert the original bytes and inode survive with nothing left behind.
  One of them pins a mistake worth naming: the "your file is at *path*"
  guidance was originally carried in the raised exception, and `SecureError`
  replaces the message it is given with a generic string unless `DEBUG=1` is
  set in the environment. The test passed only because pytest sets
  `PYTEST_CURRENT_TEST`, which flips the same switch, so it asserted a
  message no user would ever have seen.

- **Desktop GUI: dead `plugin` subcommand controls removed or rewired**
  (gitlab#188 / github#105): the GUI's keyserver, pepper and integrity
  controls called `plugin keyserver`/`plugin pepper`/`plugin integrity`
  subcommands that have never existed — `plugin` offers only `sign`,
  `trust-key` and `list-keys` — so every one failed at argparse and was
  swallowed.

  The keyserver controls are **rewired to the commands that do exist**:
  cache clearing now calls `keyserver cache-clear --force` (the `--force`
  skips a confirmation no GUI subprocess can answer), and the connection
  test calls `keyserver status`. That command takes no `--url`, so the
  button is relabelled "Check status" and reports on the *configured*
  server rather than implying the URL in the field was probed.

  The pepper and integrity controls are **kept**: their CLI surface is
  planned (gitlab#193, gitlab#194), and they are declared in the argv
  lint's known-broken registry so the gap is tracked rather than silently
  tolerated — the lint will demand those entries be deleted the day the
  subcommands land.

  One integrity defect is fixed independently of that: batch verification
  treated *any* falsy result as a hash mismatch and reported "Integrity
  verification failed - hash mismatch". The underlying call returns
  `exitCode == 0`, so it cannot tell a genuine mismatch from an
  unreachable server or a missing command — and raising an integrity alarm
  for a healthy file is the worse error. It now reports only what is
  known: that integrity could not be confirmed.

- **Whirlpool removed from the desktop GUI** (gitlab#189 / github#106): the
  GUI offered Whirlpool as a hash option and emitted `--whirlpool-rounds`,
  which no subparser declares — so any encryption configured with it exited
  2 before doing work, and the GUI swallowed the error. Whirlpool is
  decrypt-only on this line and removed entirely in 1.5, so it has no place
  in a configuration for *new* encryption.

  The option is gone from the profile editor and from both argv builders
  (the executed one and the command preview). The gating it previously sat
  behind defaulted to *showing* the option whenever CLI version detection
  failed — the moment the GUI should be most conservative — so it is
  removed rather than inverted. Profiles saved by an older build can still
  carry a whirlpool entry, so the editor filters it out rather than
  assuming it is absent.

- **stdout-leak lint authorizes individual calls, not regions** (gitlab#150 /
  github#68): the whitelist that permits a `print()` to write to stdout —
  stdout carries decrypted plaintext and derived key material, so every
  emission must be individually justified — matched on file plus line
  proximity, with a tolerance of 50 lines against a documented ±5. Each entry
  therefore authorized any stdout `print()` within 50 lines of its anchor,
  and with several anchors in one file the windows merged: in
  `recovery_slots.py` they covered 299 lines spanning the code that handles a
  generated recovery code, so turning that `eprint` into a `print` would not
  have tripped the lint added to guard exactly that file. Line drift also
  forced a manual re-anchor on nearly every commit touching a whitelisted
  file.

  Entries now state the call's own source text and how many times it may
  appear, compared against `ast.get_source_segment` for **equality** with
  whitespace and black's magic trailing comma normalized away. Equality
  rather than a prefix, because a prefix leaves everything after it
  unconstrained — adding a credential to an authorized JSON payload would
  otherwise still match. The occurrence count closes the one dimension where
  shape matching is looser than a position anchor: a second copy of an
  authorized call no longer inherits the first's authorization. Path
  suffixes are matched on component boundaries, so a vendored or
  similarly-named module cannot inherit another's entries.

  One entry was stale in a way the old scheme could not detect: the
  `usb_creator.py` entry authorized a `print(` that exists only inside a
  *generated launcher-script string*, which raw-line matching cannot
  distinguish from code — and `eprint(` contains `print(`, so the validity
  check passed on the helper it was meant to exclude. That file has no real
  `print()` call, so the entry is deleted. New tests pin properties rather
  than positions: every entry must start with a `print(` call, the whitelist
  must describe exactly the calls that exist, a `print()` adjacent to a
  whitelisted call must not inherit its authorization, an authorized payload
  extended with a credential must lose it, a vendored path must not inherit,
  and an anchor must survive its own call being reflowed.

- **Desktop GUI identity listing has never worked** (gitlab#183 /
  github#100): `CLIService.listIdentities()` runs
  `identity list --include-contacts --json`, but `identity list` declared no
  `--json` flag, so argparse exited 2 and the GUI swallowed the failure into
  empty lists. Every consumer was affected — the Identity Management screen,
  the Decrypt tab's identity selector, and the main window — so the GUI
  always showed an empty identity list with no error. Third flag in this
  series that was emitted but never existed, after `--data`/`--alias`
  (gitlab#164) and `encrypt --random`'s character-class reads (gitlab#181).

  `identity list --json` now emits a single JSON document on stdout —
  `own` and `contacts` lists of `{name, email, fingerprint, kem_algorithm,
  sig_algorithm, created_at}` — and nothing else, since the GUI feeds all of
  stdout to a JSON parser; the human report is unchanged without the flag.
  The JSON channel is deliberately **not** display-sanitized: it is
  machine-readable, the transport escapes control characters, and the
  consumer renders. Display safety therefore belongs to the renderer, so the
  GUI sanitizes at the decode boundary — where the untrusted values enter
  the app, rather than per widget, which had already missed the recipient
  picker and the signature-verification picker, the two controls that decide
  who can read the plaintext and whose signature is trusted. Its sanitizer
  now escapes rather than blanks (matching the CLI's escape-not-strip rule,
  so a spoofing attempt stays distinguishable from an unrenderable glyph)
  and covers the C1 range, the bidi/format controls, U+2028/U+2029 and the
  zero-width set; ZWNJ/ZWJ stay untouched, being load-bearing in Persian and
  Indic scripts and in emoji sequences. Flutter honours bidi overrides in
  text rendering and, unlike a terminal, treats U+2028/U+2029 as mandatory
  line breaks, so those characters are now also rejected at the CLI's own
  import boundary alongside gitlab#172's terminal-control class.

  Two failure modes that let this bug hide for the feature's whole life are
  closed with it: the GUI no longer turns a failed `identity list` into an
  empty identity list (it raises, so the screen's error banner — previously
  dead code — actually renders), and a store entry that fails to load is now
  reported rather than silently absent, in both the JSON (`skipped`) and the
  human output. Presenting a short list as complete would silently drop a
  recipient, or make an own identity look deleted.
- **Global flags after a subcommand are relocated for every subcommand, not
  half of them** (gitlab#171 / github#89): `--debug`, `--verbose`, `--quiet`
  and the other top-level flags are declared on the main parser, so argparse
  rejects them once a subcommand has been seen. `preprocess_global_args`
  exists to move them to the front, but kept its own hand-maintained copy of
  the subcommand list, and that copy had drifted to 20 of the 42 real
  subcommands. For the missing 22 — including `identity`, `keyserver`,
  `telemetry`, `plugin`, `hsm`, `test`, `sign`, `verify-signature` and the
  recovery commands — argv was returned unchanged and the subparser rejected
  the flag with exit 2. The desktop GUI appends `--debug` after the
  subcommand at 19 call sites, so with its debug toggle on every one of those
  commands failed before doing any work. Both the preprocessor and `main()`
  now read a single module-level `SUBPARSER_COMMANDS` constant, so the two
  cannot drift again; a test asserts relocation works for every entry rather
  than for a list of names that would itself need maintaining.

  Relocating a flag is only half the job — argparse parses a subcommand into a
  fresh namespace and copies every key back over the parent's, so a subparser
  that declares the same option name silently overwrites the relocated value
  with its own default. Five subparsers (`recover`, `add-recovery`,
  `remove-recovery`, `verify-integrity` and the `test` subcommands) declare
  their own `--quiet`; those now use `default=argparse.SUPPRESS` so the key
  stays absent unless the flag is actually given there. Tests assert the flag
  survives a full parse, not merely that it was moved.

  Third-party HTTP loggers (`urllib3`, `requests`, `httpx`, `httpcore`) are
  now clamped to WARNING under `--debug`. `--debug` set the *root* logger to
  DEBUG, which was previously unreachable for `keyserver` and `telemetry`
  because argparse rejected the flag; urllib3 logs the full request line, and
  the keyserver interpolates the identifier — a fingerprint or an email
  address — into the request path, so contact metadata would have reached
  stderr and the desktop GUI's persistent debug log outside the
  `debug_secret()` chokepoint.

  Two latent argv-handling bugs found in the same code are fixed: `main()`'s
  scan for the command never actually skipped `--kdf-workers`' value (both
  branches fell through to the same `continue`), so with the flag now
  relocated to the front for every subcommand the value itself would have been
  read as the command name and silently routed to the monolithic parser; and
  `-t`/`--template` was listed as a value-carrying global flag, which was dead
  code — it is a subcommand option selecting KDF parameters, and making it
  reachable would have meant `encrypt -t hardened` silently encrypting at
  default cost. `--kdf-workers=4` (the `=` spelling) is now relocated too; an
  exact-token test missed it, leaving the same symptom live for that form.

  `verify-integrity --quiet` now always prints the `Signature: VALID/NOT
  VALID` verdict. `--quiet` is documented as shortening the trust warning, but
  it had been silently dropped for this command, and once it started working
  it would have reduced a failed verification to an exit code.
- **`identity import` accepts `--data-stdin` and `--alias`; GUI contact import
  works for the first time** (gitlab#164 / github#82):
  `CLIService.importContact` has always emitted `identity import --data <json>`
  plus an optional `--alias <name>`, but the parser accepted neither — only a
  required `--file` — so every contact import from the desktop GUI died at
  argparse with exit 2. The import parser now takes `--file` and
  `--data-stdin` as a required mutually exclusive group, and `cmd_import`
  reads whichever was given.

  The document is read from **stdin rather than argv**: `/proc/PID/cmdline` is
  world-readable, so an inline flag would publish the contact's name, email
  and fingerprint to every local process — and the GUI field feeding it is a
  free-text paste box, so a mis-pasted private key or passphrase would be
  exposed at `execve`, before the CLI could reject it. Both the stdin and the
  file path now parse through `SecureJSONValidator.validate_json_security`,
  picking up the pre-parse nesting-depth scan added for #94, and a document
  that is not a JSON object is rejected with a clear message instead of a
  `TypeError` from inside `import_public`.

  `--alias` stores the contact under a local name instead of the one in the
  document. The fingerprint is computed from the algorithms and public keys
  (`calculate_fingerprint_v2`) and does not cover the name, so an alias cannot
  mask a key substitution; the alias is run through `validate_identity_name`
  because the name becomes a directory name under the identity store. The
  rename happens before `add_identity`, so TOFU key-change pinning keys on the
  name actually stored — covered by an end-to-end test that imports a
  different key under an existing alias and asserts the import is refused.

  Because the document and the interactive key-change confirmation would
  otherwise share one channel, the refusal to replace a pinned key now keys on
  the document's *source* rather than on `isatty()` alone: a pty EOF is soft,
  so a supplier sending `{...}<^D>yes` could otherwise have answered its own
  trust prompt. A stdin-sourced document never reaches the prompt and always
  requires `--allow-key-change`.

  Both input paths are read through a shared bounded read, so the file path is
  no longer materialised before its size is checked, and `--file` now requires
  a regular file — a FIFO or `/dev/zero` previously passed the `exists()`
  check and blocked forever. Identity documents are read and written as UTF-8
  explicitly rather than in the locale default, under which a name or email
  could round-trip to different characters while the ASCII key fields kept the
  fingerprint check passing.
- **Desktop GUI: main screen no longer asserts on teardown** (gitlab#143 /
  github#61): `_MainScreenState.dispose()` cleaned up the debug overlay through
  `_hideDebugWindow()`, which calls `setState()` — but by the time `dispose()`
  runs the element is already defunct, so Flutter's
  `_lifecycleState != _ElementLifecycle.defunct` assertion fired on every
  shutdown of the main screen in debug builds (in release builds assertions are
  compiled out, but marking a defunct element as needing rebuild is still
  wrong). `dispose()` now detaches the overlay entry through a new
  `_removeDebugOverlay()` helper that touches no widget state; the interactive
  hide path keeps its `setState()`. Covered by a teardown regression test.

- **`template list --format json` now emits JSON** (gitlab#167 / github#85):
  `--format {table,json}` was declared and never read, so a caller could request
  the machine-readable form, receive exit 0, and get nothing on stdout. The
  document is now written to stdout with the human report left on stderr, and
  `template` no longer exits 0 for an unrecognised subcommand. The payload
  deliberately omits the security score and level: for the metadata-bearing
  template format those are taken verbatim from the file and never recomputed,
  and templates are ranked by that value, so publishing it as an authoritative
  rating would be the wrong direction to resolve that in (gitlab#169). Every
  remaining field is length-bounded and type-coerced, since a template file is
  any document a local process can place in the template directory.

- **`telemetry` reports failure through its exit code** (gitlab#166 /
  github#84): the command ended in an unconditional `sys.exit(0)`, and every
  failure inside the handler — plugin unavailable, plugin initialisation
  failure, a refused `opt-out`, a failed `flush` — only printed to stderr and
  returned. A caller could not tell a completed opt-out from one that never
  happened, which matters because opt-out is destructive: it deletes pending
  events and the API key. Any wrapper checking the exit status would have
  reported a user's telemetry data as deleted when it was not, or cleared local
  state believing a failed upload had succeeded. Declining the confirmation
  prompt now returns a distinct status as well, so a caller can tell "the user
  said no" from "done" and from "it broke". The success message no longer
  overstates the effect: opt-out writes no persistent setting, so telemetry can
  be switched on again by `OPENSSL_ENCRYPT_TELEMETRY=1` or a config file, which
  registers a new key.

- **`analyze-config` no longer claims post-quantum protection that is not
  configured** (gitlab#166 / github#84): `--pqc-algorithm` defaults to the
  string `"none"`, and five separate places tested the raw value for
  truthiness, which a non-empty string satisfies. The report therefore said
  `post_quantum_enabled: true`, `post_quantum_ready: true` and estimated
  longevity as "quantum-resistant" for a configuration with post-quantum off,
  while suppressing the recommendation to enable it — asserting a protection
  the user did not have and withholding the advice that would provide it. All
  five now use one predicate that normalises the value, so `"none"`, `"None"`,
  whitespace, empty and non-string values are treated as absent. The reported
  overall score for such a configuration drops slightly, because it no longer
  receives a post-quantum bonus it had not earned. Correcting this also exposed
  a latent crash: the branch recommending post-quantum encryption was
  unreachable while the flag was wrongly read as enabled, and it indexed
  `--use-case`, which argparse leaves as `None` rather than empty — so
  `analyze-config` with no options now runs instead of failing.

- **Telemetry confirmation prompts no longer traceback without a terminal**
  (gitlab#166 / github#84): `telemetry clear` and `telemetry opt-out` called
  `input()` directly, so a caller with no usable stdin — a GUI subprocess or a
  CI job — got an `EOFError` traceback and an exit code outside the command's
  own contract. Both now treat that, and an interrupt, as a decline. Declining
  returns status 3 rather than 2, so it cannot be confused with argparse's
  usage-error code.

### Security

- **A contact stored under an own identity's name can no longer substitute
  its keys** (gitlab#173, ADVISORY 2026-15): `get_by_name` resolves own
  identities before contacts, but `add_identity` chose its destination purely
  from whether the identity was an own one. Importing a contact whose name
  matched an existing own identity created a *shadowed* contact entry —
  invisible while the own identity existed, because every lookup resolved the
  own identity first. `delete_identity` removed only the first location it
  found, so deleting the own identity left the shadow behind and `get_by_name`
  then resolved to the contact's keys under a name the user trusts. Since
  recipient resolution goes through `get_by_name`, that is a live key
  substitution: files encrypted to that name go to the attacker's key. The
  TOFU key-change dialogue does fire on the import, but it is a gate about a
  *changed key* — designed to be passable with `--allow-key-change`, and
  silent when the fingerprints happen to match.

  `add_identity` now refuses a name that already exists as the other kind, in
  both directions and independently of the key-change gate: one name resolves
  to one key, so the collision fails closed on its own. `delete_identity`
  removes both locations, so a store that already contains a shadow cannot
  promote it. `IdentityStore.find_shadowed_names()` reports colliding names,
  and `identity list` surfaces them in both its human output and its `--json`
  document (a `shadowed` key), so an existing shadow is visible rather than
  silent.

  Review of the fix caught that deleting both sides had become a trap: the
  warning told users to remove "the one you did not intend to keep", but
  `identity delete` had no way to do that and removed both — destroying the
  own identity's private keys (making every file encrypted to it unreadable)
  *and* the contact's TOFU pin, so a later import of that name would be
  accepted as first use with no key-change warning at all. `identity delete`
  now takes `--kind own|contact|both` (default `both`), shows both entries
  and both fingerprints before the confirmation, and says what each deletion
  costs. `contacts` is also reserved as an entry name: it is the store's own
  container directory, so an entry of that name was written *into* it —
  unlistable yet resolvable, and deleting it would have removed every pinned
  contact in the store.

- **Imported identity email can no longer forge the fingerprint line with
  terminal escapes** (gitlab#172, ADVISORY 2026-14): `Identity.import_public`
  validated the identity name but took `email` completely raw, and the CLI
  printed it unsanitized directly above the `Fingerprint:` line in
  `identity import`/`list`/`show`. A JSON string may carry `\u001b` escape
  sequences — the JSON security validator rejects only *literal* control
  characters, whose escaped source text is printable — so a crafted bundle's
  email could move the cursor and overwrite the genuine fingerprint with one
  the victim trusts. Out-of-band fingerprint comparison is the only
  authenticity mechanism the identity design has, so forging that readout
  enables exactly the key substitution the TOFU ceremony exists to surface.
  The same class existed on error paths: a rejected identity name or
  `--alias` was interpolated verbatim into the `IdentityError` message the
  CLI echoes.

  Security review of the fix found the same class live on **every other
  identity display surface**, including one reachable by a fully remote
  attacker: the keyserver TOFU trust prompt printed a fetched bundle's
  `name`/`email`/`created_at` raw around the very fingerprint it tells the
  user to verify out of band (`created_at` is printed *after* the
  fingerprint and was completely unconstrained) — and the bundle's
  self-signature is no defence, since it verifies against the signing key
  shipped *in* the bundle. `identity create --email` was the producer-side
  gap: the value is exported verbatim and uploaded, attacking other users'
  prompts. Stored identity files were a third channel (an
  `--identity-store` directory from an archive or shared folder feeds
  `list`/`show` and the TOFU key-change warning without any import-time
  check), and a signature sidecar leaked through three fields: its
  `signer_fingerprint` printed on the unknown-signer error path before any
  cryptographic check, its `algorithm` echoed by the unsupported-algorithm
  error pre-verification, and its display-only `component` name — deliberately
  excluded from the signed payload, so any tamperer can rewrite it on a
  *valid* signature — printed inside the ✅ GOOD-signature verdict block. A
  keyserver's raw HTTP error body (unbounded remote text) also reached the
  terminal through exception messages.

  The fix validates at every boundary and sanitizes at every display:
  `import_public`, `Identity.generate`, `Identity.load`, and
  `PublicKeyBundle` now validate `email` (string, ≤ 320 chars, no control
  characters), `fingerprint` (the colon-separated lowercase hex shape the
  tool has always written), and `created_at` (≤ 64 chars, no controls);
  `parse_signature` format-validates `signer_fingerprint`, `algorithm`, and
  every `component` name; keyserver HTTP error bodies are truncated and
  sanitized; and `identity.json` is read bounded, explicitly UTF-8, and
  through the JSON security validator, so a hostile store directory cannot
  DoS `identity list`. A display
  sanitizer escapes C0 controls, DEL, the C1 range (one-byte CSI
  introducers included), backslash (so escaped output is unambiguous), and
  the bidi/format controls (which VTE/Kitty honour and which can visually
  reverse an email within its line) at every terminal display of identity
  name/email/fingerprint, the keyserver trust prompt and `keyserver search`
  display, the TOFU key-change warning, the verified-signature sender line,
  and every identity CLI error path. Escaping rather than stripping keeps
  the evidence visible — the user sees `\x1b[1A` instead of having their
  display rewritten. Contacts and cached keyserver bundles imported by
  earlier versions with crafted fields are neutralized at display time by
  the same sanitizer.
- **`encrypt --random` has a safe delivery channel for the generated password**
  (gitlab#152 / github#70): the password was printed to **stderr** in a banner,
  held for a 10-second countdown, then "cleared" with ANSI escapes. stderr is
  merged into stdout by `2>&1` and lands in terminal scrollback, `script(1)`
  transcripts, CI job logs and the desktop GUI's persistent debug log; the
  screen-clear repainted the visible screen and removed the password from none
  of those. A non-interactive caller had no way to receive it at all.

  `--random-password-out PATH` now writes it to a file created 0600 through the
  same hardened primitive as the recovery-code channel (gitlab#146): `O_EXCL`
  and `O_NOFOLLOW`, non-regular and foreign-owned targets rejected, mode pinned
  with an unconditional `fchmod`, and both the file and its directory entry
  fsynced. Naming a destination replaces the display rather than adding to it,
  and a destination equal to `--input` or `--output` is refused — equal to the
  output it would have been truncated by the ciphertext write moments later,
  sealing the file under a password that no longer existed anywhere, and
  reporting success.

  A destination is **required** whenever the password cannot be displayed:
  stderr not a terminal, or `--quiet`, which suppresses the banner entirely.
  Encrypting anyway would have produced a file nobody could open. The password
  is now delivered *before* the file is encrypted, on both channels — disclosing
  after the ciphertext is written means any later failure (armor, steganography,
  the permissions call, the audit log) leaves an encrypted file whose password
  was never shown. If encryption then fails, the password file is deliberately
  **not** deleted — a failure does not prove the ciphertext was not written —
  but its existence is now reported.

  The retained terminal display no longer claims to erase anything; it states
  plainly that the password is in scrollback and in any transcript of the
  session. The generated password is also registered with the audit-log
  redactor, which its shape heuristic would not otherwise match.
- **`encrypt --random` crashed instead of running** (gitlab#181 / github#96):
  the handler read `args.use_lowercase` and three siblings, which are declared
  on `generate-password` and on the monolithic parser but not on the `encrypt`
  subparser — and `encrypt` always routes through the subparser. The feature
  had never worked, which also means the stderr display above was unreachable
  in practice. The reads now default to all character classes enabled.
- **`keyserver login <client_id>` no longer appears in the `--debug` argv dump
  or in the keyserver logs** (gitlab#171 / github#89): `client_id` is a
  positional argument, so `SECRET_VALUE_CLI_OPTIONS` — which matches option
  *names* — could not redact it, and the login request body is
  `{"client_id": ...}` with the password optional, meaning the client_id alone
  yields access and refresh tokens. `sanitize_argv_for_debug` now redacts the
  value following any subcommand in the new `SECRET_POSITIONAL_SUBCOMMANDS`
  set (`set-token`, `login`), and three `logger.info` calls in the keyserver
  plugin no longer interpolate the client_id. Newly *reachable* rather than
  newly introduced, and only on this development branch: until the global-flag
  fix in this release, argparse rejected `--debug` after `keyserver`, so
  neither code path could run in any released version.
- **Third-party HTTP loggers are clamped under `--debug`** (gitlab#171): the
  `--debug` handler sets the *root* logger to DEBUG, and urllib3 logs the full
  request line. The keyserver interpolates the identifier — a fingerprint or
  an email address — into the request path, so enabling `--debug` for
  `keyserver`/`telemetry` would have written contact metadata to stderr and to
  the desktop GUI's persistent debug log, outside the `debug_secret()`
  chokepoint. `urllib3`, `requests`, `httpx`, `httpcore` and `asyncio` are now
  held at WARNING.
- **Plugin sandbox no longer authorizes sibling directories via a bare path
  prefix** (gitlab#133 / F15, GHSA-vr4h-5xqv-xxxf): `PluginSandbox._is_safe_path` allowed a
  path with a plain string-prefix match, so a sandboxed plugin `foo` (without
  `READ_FILES`) could read/write another plugin's directory `.../plugins/foobar`
  because it shared the `.../plugins/foo` prefix — a cross-plugin access break
  within the same user. Each allowed directory is now matched as itself or with a
  trailing separator (`dir` / `dir + os.sep`), so a prefix-sharing sibling is
  refused.

- **Keyserver bearer token is redacted in the `--debug` argv dump** (gitlab#134 /
  F17, GHSA-jqqp-pf9j-889j): the `keyserver set-token <token>` positional bearer token was
  echoed in cleartext by the `--debug` `sys.argv` dump (even without
  `--unsafe-show-secrets`), persisting the credential in logs/terminal history.
  The positional after `set-token` is now routed through the `debug_secret`
  redaction chokepoint like other secret CLI values.

- **Trust-anchor enrollment requires the full fingerprint (no suffix match)**
  (gitlab#136 / F21, GHSA-xg52-638v-jc5m): `enroll_trust_key` bound a plugin-signing trust
  anchor using suffix-tolerant matching, so confirming a short (forgeable) GPG
  key id could enrol an attacker's colliding key — which then vouches for
  malicious plugins under the ENFORCE signature policy. Enrollment now requires
  the confirmed value to equal the full primary-key fingerprint exactly
  (case-insensitive, whitespace-stripped); short/partial confirmations are
  rejected.

- **PIV smartcard PIN materializes one fewer unwipeable copy** (gitlab#135 /
  F20): `TokenSession.login` decoded the PIN through an intermediate immutable
  `bytes()` before the `str` the PKCS#11 binding requires, leaving an extra
  non-zeroable plaintext PIN copy on the heap. It now decodes the wiped bytearray
  directly, so only the binding-required `str` (an accepted, minimized-lifetime
  residual) is materialized; the PIN bytearrays are still zeroized. Memory
  hygiene only — no behavior change.

- **Portable-USB integrity now detects added executables and protects
  root-level autorun files; the hash-manifest fallback uses the per-drive salt**
  (gitlab#132 / F13 + F19, GHSA-8jx3-27qf-3p97): the module's threat model
  treats the removable drive as untrusted (physical write access). Integrity
  verification previously only re-hashed the files listed in the manifest, so a
  file **added** to the drive — including a root-level `autorun.*` payload (which
  lives above the portable directory and is auto-executed by the OS on insert) —
  was never noticed and verification still passed. New drives now write a v2
  integrity manifest that is an **allowlist** of every file in the tool tree
  (plus the root `autorun.inf`/`autorun.sh`/`.autorun` hashes), so verification
  flags **any** file added afterward — a planted `.dll`/`.so`/`.pyd`/`.exe` or
  any other payload, not just a fixed set of extensions — and any tampered,
  added, or removed root autorun file. The user's mutable workspace (`data/`)
  and `logs/` are excluded, so the normal use case (encrypting files onto the
  drive) still verifies. Drives created before this fix carry no v2 marker and
  verify exactly as before (backward compatible); re-create a drive to gain the
  stronger checks. Separately, the cryptographic hash-manifest
  fallback path derived its key with the global fixed salt (F19); it now uses the
  drive's unique per-drive salt (`salt.bin`), matching the main key-derivation
  path already hardened earlier.

- **The weak 10k-PBKDF2 dual-encryption file-password verifier is no longer
  trusted; the mismatch state fails closed** (gitlab#131 / F18,
  GHSA-fmjx-p826-6fvr): dual-encrypted files carried a `pqc_dual_encrypt_verify`
  hash — a 10,000-iteration PBKDF2 pre-check over the file password stored in
  cleartext metadata — that an attacker with the file could brute-force offline
  to recover the second-factor file password. That pre-check is no longer
  recomputed or trusted (and is no longer propagated into re-processed
  metadata): the file password is authenticated by the dual-encryption AES-GCM
  tag during keystore key retrieval, which derives the file key with the
  keystore's own Argon2id KDF and is not brute-forceable offline. The one state
  where the AES-GCM tag would not gate the file password — a file that claims
  dual encryption backed by a non-dual keystore key entry (a metadata/keystore
  mismatch) — now fails closed in `get_key`, so removing the weak pre-check
  cannot let a wrong file password through. Legacy dual-encrypted files still
  decrypt unchanged; re-encrypt them to drop the weak verifier from their
  metadata.

- **`.pqc` keyfiles wrap the private key with Argon2id instead of PBKDF2-SHA256
  100k** (gitlab#131 / F16, GHSA-fmjx-p826-6fvr): a keyfile created with
  `--pqc-keyfile` wrapped the long-lived PQC private key under a key derived
  from a single PBKDF2-HMAC-SHA256 pass at 100,000 iterations — below the OWASP
  floor and far weaker than the Argon2id used for file and keystore material, so
  an attacker who obtained the keyfile could brute-force the wrapping password
  cheaply offline. New keyfiles now derive the wrapping key with Argon2id and
  record a self-describing `key_kdf` descriptor; the redundant trailing SHA-256
  is dropped. Existing PBKDF2-wrapped keyfiles still decrypt unchanged (no
  `key_kdf` → legacy path). The Argon2 cost read from a keyfile is bounded
  (memory ≤ 2 GiB, time ≤ 64, parallelism ≤ 16) so a tampered keyfile cannot
  OOM the host on decrypt before the AES-GCM tag authenticates. Re-wrap existing
  keyfiles (regenerate or re-save) to move them onto Argon2id.

- **Unsigned third-party plugins are refused by default (signature policy now
  ENFORCE)** (gitlab#130, GHSA-587j-4r3v-cm2c): the plugin loader defaulted to
  `warn`, so an unsigned/unverifiable non-built-in plugin was exec'd in the host
  process after only an AST denylist scan — a scan that is bypassable (e.g.
  `getattr`/`__import__` indirection), giving arbitrary code execution to anyone
  who could drop a `.py` into a plugin directory. The default signature policy is
  now `enforce`: a non-built-in plugin must carry a valid detached signature from
  an enrolled trust anchor or it is refused before its code is imported. Built-in
  bundled plugins keep their trust shortcut and are unaffected, so no shipped
  functionality changes. Users who deliberately load unsigned third-party plugins
  can opt back into the old behavior with
  `OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY=warn` (or `off`), or an explicit
  `signature_policy=` argument; an unrecognized env value now fails closed to
  `enforce` with a warning rather than silently weakening the policy.
  Additionally, the built-in trust shortcut is now scoped to the genuinely
  shipped plugin subtree: the advertised third-party drop directories
  (`plugins/user`, `plugins/community`, `plugins/official`) are no longer
  treated as built-in, so a plugin placed there must pass the full signature +
  AST + TOCTOU gate — otherwise the ENFORCE default would have been bypassable
  by dropping an unsigned plugin into the directory the tool advertises for
  third-party plugins.

- **Decryption refuses crafted files/keystores whose KDF cost would exhaust
  memory** (gitlab#128, GHSA-7894-5gw8-69hr): Argon2 `memory_cost`, scrypt `N`,
  and balloon `space_cost` read from file metadata (and from a keystore header)
  were passed to the KDF before authentication with no upper bound — scrypt's
  own `maxmem` guard was even computed from the attacker-supplied `N`, so it
  could never trip. A single crafted file could drive a multi-terabyte
  allocation and OOM-crash the host on decrypt, with no correct password
  required. Decryption now estimates peak memory before any KDF runs and refuses
  when it exceeds an 8 GiB safety ceiling — 4× the largest shipped preset, so no
  legitimately written file is affected — overridable per file with
  `--allow-high-kdf-cost` or an interactive confirmation (users may still choose
  expensive parameters for their own files). The same ceiling is enforced on
  every key-derivation path that consumes untrusted metadata — standard and
  streaming decrypt, the envelope rekey fast-path, recovery-slot add/remove,
  asymmetric `--no-verify` decrypt, and the PQC keystore header — and the scrypt
  memory estimate (previously under-reported as zero, which would have let a
  high-`N` file slip past the ceiling) is corrected. CPU/time cost stays
  advisory — only memory, which OOM-kills uninterruptibly, is hard-guarded.

- **Identity-file unlock bounds its Argon2 cost parameters** (gitlab#129,
  GHSA-783h-8q2f-f762): an identity file's password-protection block carried an
  unbounded `memory_cost` read straight from JSON, and `_derive_key` fed it to
  Argon2 before the AEAD tag authenticated the private key — a tampered or
  attacker-authored identity with a gigabyte-scale `memory_cost` OOM-crashed the
  host on unlock, pre-authentication (same class as gitlab#128 on the
  identity-file surface). The Argon2 cost parameters are now clamped to sane
  maxima (memory ≤ 2 GiB, time ≤ 64, parallelism ≤ 16) before derivation.
  Legitimate identities use the 64 MB default, far under the cap, so no file
  changes behavior.

- **Balloon KDF fails closed on v14+ metadata missing `space_cost`**
  (security review 2026-07-13 INFO-2, gitlab#125): the decrypt-side
  derivation fell back to the historically weak `space_cost=16` whenever
  the field was absent from balloon metadata. That fallback is load-bearing
  for v11 files written by released v1.4.0–v1.4.3 (pre-M3, guarded by
  `test_balloon_defaults_m3.py`) and is kept for v11–13 — but v14 postdates
  the M3 fix, so every released v14+ writer persists the field; a missing
  `space_cost` at v14+ can only be crafted or corrupted metadata and now
  raises a clear `ValueError` instead of silently deriving with ~512 bytes
  of memory hardness. The parallel KDF path needs no gate of its own (v13+
  parallel dispatch delegates to the sequential, gated path — invariant now
  pinned by a test). No legitimately written file changes behavior.

- **The legacy no-hash-iterations KDF seed is now wipeable and wiped**
  (security review 2026-07-13 INFO-1, gitlab#124): with no hash iterations
  configured, `generate_key` built its seed as the immutable concatenation
  `password + salt + hsm_pepper`, which the existing wipe at the return
  site silently refused (M10 — immutable input). The seed is now written
  into one exact-size `bytearray` through a memoryview and is effectively
  zeroized in the `finally`, including when a KDF rebinds the working
  variable. Legacy sequential formats only; derived keys are byte-identical
  (pinned by golden-value regression tests).

- **`derive-password` no longer leaves the HSM pepper and derived-key
  copies unwiped** (security review 2026-07-13 LOW-1, gitlab#123): the
  handler held the hardware pepper as immutable bytes that were never
  zeroized, and "cleaned up" the derived key by wiping a throwaway
  `bytearray(key)` copy while the printed output slice stayed resident.
  The pepper is now held in a wipeable buffer from acquisition (a mutable
  plugin buffer is wiped in place), the truncated output is copied into a
  `bytearray` via a memoryview (no intermediate immutable slice), and both
  are zeroized in a `finally` on all exit paths. The immutable `bytes`
  returned by `generate_key` remains a documented accepted residual (M10
  design, common to all callers). Derived outputs are unchanged.

### Internal

- **Desktop GUI widget tests: corrected button finders**: the Rekey and Secure
  Shred screen tests looked their action button up with
  `find.widgetWithText(ElevatedButton, ...)`, but both buttons are built with
  `ElevatedButton.icon`, whose runtime type is the private
  `_ElevatedButtonWithIcon` subclass. `find.byType` compares `runtimeType`
  exactly and does no subtype test, so those finders matched nothing and the
  tests could never pass. They now match on `find.bySubtype<ElevatedButton>()`.
  The Rekey tap test additionally calls `ensureVisible()` first — the button
  sits below the fold of the 800x600 test viewport, so the tap previously
  missed silently.

- **Completed plan documents removed from `docs/`** (plan-tracker
  verification 2026-07-13, mirroring the 1.5.x cleanup):
  `FORMAT_V14_PLAN.md`, `FORMAT_V14_IMPLEMENTATION_PLAN.md`,
  `V14_REVIEW_LOW_FIX_PLAN.md` and `V14_REVIEW_FIXES_2026-07-10.md` — all
  steps verified implemented in this branch's code before removal;
  recoverable via git history.

- **`KDF_CHAIN_SECURITY_RESEARCH.md` moved** from the repo-root `docs/`
  into the package documentation (`openssl_encrypt/docs/`), joining the
  other shipped guides.


## [1.4.8] - 2026-07-12

### Added

- **Documentation: KDF-chain security research report**
  (`docs/KDF_CHAIN_SECURITY_RESEARCH.md`): literature review (verified,
  cited) on the security of sequential/chained KDF constructions vs.
  parallel XOR combiners — robust-combiner theory, cascade counterexamples,
  generic-attack bounds, and the open questions relevant to this project's
  KDF cascade design.

- **`check-password` command**: a read-only subcommand that reports the strength
  of a password without encrypting anything. Prints the pattern-aware strength
  category, entropy (pattern-aware and raw), detected-weakness warnings, and
  pass/fail against a chosen `--password-policy` (with `--strict-strength`
  supported). The password is read from `CRYPT_PASSWORD`, a piped stdin, an
  interactive prompt, or (discouraged, with a warning) the `-p`/`--password`
  flag. Human output goes to stderr; `--json` emits a machine-readable report on
  stdout. Exits non-zero when a policy is applied and the password fails it, so
  it can be used as a scriptable gate. (Backported from 1.5.x.)
- **Pattern-aware password strength estimation**: password strength feedback now
  detects predictable structure (dictionary words, l33t substitutions, keyboard
  walks, ascending/descending sequences, repeats, dates) instead of relying on
  the raw character-space entropy alone, which over-rated structured passwords
  (e.g. `Password1!`). Uses the optional [`zxcvbn`](https://pypi.org/project/zxcvbn/)
  package when installed, and a built-in heuristic fallback otherwise — `zxcvbn`
  is **not** a production dependency. Behaviour is **advisory by default**: the
  displayed strength label and new "Password weakness" warnings reflect the
  pattern-aware estimate, but the `--min-password-entropy` gate still uses the
  raw measure, so passwords accepted before remain accepted. The new
  `--strict-strength` flag (enabled automatically by the `paranoid` policy) makes
  the gate reject passwords whose pattern-aware strength is too low. This only
  affects password validation when encrypting; it never affects decryption.
  (Backported from 1.5.x.)

### Fixed

- **Test: `test_fallback_notice_respects_quiet` is now deterministic
  against the environment** (gitlab#122, 2026-07-12): the CI test job
  exports `PQC_QUIET=true`, and `PQCipher.__init__` computes
  `self.quiet = quiet or PQC_QUIET` — so the test's `quiet=False`
  reader was forcibly quiet in CI, the legacy-KEM-derivation notice
  never appeared, and the assertion failed on release-branch/tag
  pipelines (the only pipelines that run the test job; `feature/*`
  pipelines skip it, which is why this never surfaced during
  development). The test now patches the module-level `PQC_QUIET`
  constant to `False` so it exercises the `quiet` parameter itself.
  Product behavior is unchanged — `PQC_QUIET` is a deliberate global
  silencer and correctly suppresses the notice.

- **Legacy-KDF retry classification is now structural** (v14 follow-up
  review LOW-4, gitlab#116, 2026-07-11): two classification gaps in the
  v12/v13 legacy-KEM-key retry — both fail-closed, none attacker-usable.
  (1) The adapter retry caught only `cryptography.exceptions.InvalidTag`,
  but the custom XChaCha20Poly1305 wrapper converts that into the
  project's `AuthenticationError`, so adapter-path xchacha legacy files
  skipped the retry — it now catches both. (2) The native classifier was
  over-broad (`except Exception`), converting structural errors (e.g.
  "Ciphertext too short") into "authentication failure" and triggering a
  pointless retry, contradicting the `decrypt()` docstring — it is now
  narrowed to `(InvalidTag, AuthenticationError)`. (The 1.5.x threefish
  part of this finding does not apply: Threefish is not a PQC data
  cipher on this line.) The retry remains scoped to v12/v13 and
  AEAD-gated; v14+ still never retries.


- **Keystore dual-encryption metadata gates excluded v11-v14 files**
  (pre-existing, surfaced by the v14 default flip): `keystore_wrapper` and
  `keystore_utils` checked `format_version in [4..10]` before looking up
  embedded PQC keys, key IDs, and the dual-encryption flag in the v4+
  hierarchical metadata — files at v11-v13 (including the v13 template
  default of released 1.4.6/1.4.7) fell into the legacy root-level branch
  and keystore dual-encryption failed. All gates generalized to `>= 4`,
  matching the crypt_core fix.

- **RandomX component crashed independent-XOR derivation for wide-key
  algorithms** (pre-existing): the RandomX KDF natively yields 32 bytes, so
  with AES-SIV or Threefish-512/1024 (64/128-byte keys) the independent-XOR
  combiner refused to XOR mismatched lengths and key derivation crashed.
  The component output is now HKDF-normalized to the target key length
  (byte-identical pass-through for 32-byte keys; mismatched configs never
  produced a file, so nothing existing is affected). The KDF-without-
  prior-hashing interactive warning and the HKDF-only rejection (#99) are
  also enforced on the independent-XOR path now that it is the default.

- **Sequential XOR + streaming silently produced undecryptable files** (found
  while wiring the v14 default flip, verified against the previous release
  code): requesting `--use-xor-composition` on a file above the streaming
  threshold derived the key sequentially but wrote a v12 streaming file,
  which the decrypt router always routes down the independent-XOR path —
  every such file failed chunk authentication (data loss). The combination
  is now refused with a clear error pointing to `--no-streaming` (which
  round-trips correctly at v13-sequential) instead of writing a file that
  cannot be decrypted.

- **Embedded encrypted PQC private keys in v11-v13 files were undecryptable**
  ("Missing PQC key salt"): the decrypt-side `pqc_key_salt` lookup was gated
  on `format_version in [4..10]`, so files that embed a password-encrypted
  post-quantum private key (`pqc_store_private_key`) at format versions 11-13
  always fell into the v3 legacy branch and failed. Every v4+ metadata writer
  stores the salt under `encryption.pqc_key_salt`; the gate is now `>= 4`,
  with v13/v14 regression round-trips. Found while wiring format_version 14.

### Added

- **Format-version fixture corpus** (v14 implementation plan Phase 5):
  pre-encrypted fixtures under `unittests/testfiles/format_versions/` pin
  the decrypt path of every supported write topology — v9 plain, v11/v13
  independent-XOR, v13 sequential-XOR, v12/v14 streaming, v13/v14 PQC with
  HKDF and transcript-bound KEM keys, and a pre-1.4.8 legacy-KDF PQC file
  that permanently pins the bare-SHA256 decrypt fallback. A failure in this
  suite means reading existing files broke.

### Changed

- **Visible notices for legacy-format writes** (post-v14 review
  INFO-1/INFO-2, 2026-07-11, warn-only — never an error): requesting an
  explicit `format_version` below the current default for a NEW encryption
  now prints a warning (the file lacks the v14 `#100`/`#83` protections;
  explicit versions remain honored for API compatibility), and the
  streaming path's silent version upgrade is now announced with a visible
  note instead of a debug-only log line (streaming can only write v12 or
  v14; the upgrade itself is unchanged). Also corrected a misleading
  comment that claimed streaming PQC files exist (no PQC hybrid algorithm
  can stream), so future binding-coverage audits aren't misled (INFO-3).

- **format_version 14 scaffolding** (v14 implementation plan Phase 1, no
  default/behavior change for existing writes): registered
  `metadata_v14_schema.json` (independent-XOR only — `xor_mode` enum is
  `["independent"]`; optional v12-style `streaming` block), added
  `LATEST_STABLE_FORMAT_VERSION = 14`, extended explicit `xor_mode` stamping
  from `== 13` to `>= 13`, added a fail-closed guard refusing any
  `format_version >= 14` write with sequential XOR (sequential stays pinned
  at v13 per the M2 decision), and generalized hardcoded decrypt-side
  version lists (`[4..13]` → `>= 4`, `[8..13]` → `>= 8`) so future versions
  cannot silently fall into legacy branches. Per crypto-review of the phase:
  the sequential-refusal fires before the streaming force-to-12 rewrites the
  version (size-independent invariant), the no-validator JSON fallback now
  fail-closes on unknown/future format versions instead of relying solely on
  schema validation, the v14 schema requires `xor_mode`, and the decrypt
  router treats `format_version >= 14` as independent-XOR explicitly. v14
  files round-trip; nothing writes v14 by default yet.

- **Documentation: `docs/FORMAT_V14_IMPLEMENTATION_PLAN.md` added — v14
  scheduled for 1.4.x** (2026-07-10): phased execution plan for the full v14
  scope (#100 TLV KDF seed, #83 KEM HKDF + ciphertext binding, M2
  independent-XOR default / M1) on `feature/v1.4.x-development`, followed by
  a full 1.5.x port with byte-identical golden vectors. All implementation
  sites re-verified on 1.4.x. Documents a critical planning finding: the
  FORMAT_V14_PLAN §3.6 claim that the #83 v12 HKDF ancestor exists on both
  lines is wrong — 1.4.x still derives KEM keys as bare
  `sha256(shared_secret)` with no `format_version` threading, a suspected
  live cross-line incompatibility for v12/v13 PQC files (to be confirmed and
  fixed as Phase 0). Plan only — no code change.

- **Documentation: `docs/FORMAT_V14_PLAN.md` M2 decided as Option A**
  (decision record, 2026-07-10): format_version 14 writes will default to the
  independent-XOR topology; sequential-XOR (`--use-xor-composition`) remains a
  supported opt-in pinned at format_version 13; the whole-chain HKDF
  finalization fallback is rejected. Under this topology M1 is closed for v14
  writes by construction (the independent scrypt component already derives the
  full key length). Also records the verified code state behind the decision:
  sequential-XOR is a hybrid (chains and XOR-accumulates, shares the M1 scrypt
  site), decrypt dispatch is fully metadata-driven (existing v8–v13 files are
  unaffected by the default flip), and the bare/template invocations already
  force independent-XOR, so the sequential-cascade default only affects custom
  KDF configs. Decision record + spec update only — no code change.

- **Documentation: `docs/FORMAT_V14_PLAN.md` extended with KDF-cascade audit
  findings** (addendum, 2026-07-09): pre-staged v14 specs for M1 (scrypt
  sequential stage truncates the intermediate to 256 bits for 512/1024-bit
  keys) and M2 (default v9 path is a pure sequential cascade with a
  weakest-link floor; make Independent-XOR the default or add a whole-chain
  finalization step). Spec/plan only — no code change.

- **`--debug` warning is now proportional to what it leaks**: the loud
  "SENSITIVE DATA LOGGING ACTIVE" banner and the "do not use on production data"
  notice now fire only for `--debug --unsafe-show-secrets` (the path that prints
  secrets in cleartext). Plain `--debug`, which redacts every secret to length +
  a keyed SHA-256 fingerprint, now shows a calm, accurate note instead — stating
  that secrets are redacted, that secret lengths and public values (nonces,
  salts, ciphertext) are still written to stderr and may persist in logs or
  shell history, and that `--unsafe-show-secrets` reveals cleartext. The old
  always-on alarming banner both overstated the risk of the redacted path and
  desensitised users to the real cleartext warning. Message-only change; no
  redaction logic was altered.

### Security

- **The live `hsm fido2-test`/`onlykey-test` handlers no longer print the
  derived hardware pepper** (H1 [HSM-1] residual, gitlab#121, 2026-07-12):
  the 2026-07-07 H1 fix removed the pepper hex dump from
  `modules/hsm_cli.py`, but that click-based frontend is not wired into the
  `openssl-encrypt` entry point — the `hsm` subcommand dispatches to
  `handle_hsm_command` in `crypt_cli.py`, whose `fido2-test` and
  `onlykey-test` handlers still hex-dumped the full pepper. Both now report
  only the pepper length. Mitigating: the printed pepper was derived from a
  random per-invocation test salt, so it unlocks no real file — but it is
  hardware-derived key material and must never reach output. Fixed in the
  same sweep: the FIDO2 pepper plugin interpolated the raw prf/hmac-secret
  output (the pepper's source material) into a `logger.debug` line and into
  a `PluginResult` error message that reaches the user via
  `eprint(result.message)` — both now render structure only (type/keys);
  and the `asymmetric_core` `__main__` self-test printed 32 bytes of its
  (random, throwaway) roundtrip password as hex on failure — now lengths
  only. The H1 regression test now scans the live `crypt_cli.py`, the
  OnlyKey/YubiKey challenge-response plugins, and every `prf_data` sink
  (logs, prints, plugin error messages), not just `hsm_cli.py`.

- **SECURITY.md advisories recorded for the 1.4.8 security batch**: new
  ADVISORY 2026-03 (plugin signature verification gaps — unverified
  package siblings H2 [PLUGIN-1], verify/execute byte mismatch M1
  [PLUGIN-2]) and ADVISORY 2026-04 (cleartext secret material in
  diagnostic/debug output — HSM test-command pepper prints incl. the
  gitlab#121 live-path residual / GHSA-p9g8-wvh4-2jmx, per-round KDF
  debug intermediate, plugin prf_data sinks, self-test print); the
  ADVISORY 2026-02 mitigation now notes that 1.4.8 refuses new v8/v10
  writes and that `rekey` upgrades inherited v8/v10 files.

- **`encrypt_file` now refuses format_version values above the latest
  stable format** (v14 follow-up review LOW-2, gitlab#114, 2026-07-11):
  the write path bounded explicit `format_version` requests from below
  (the v8/v10 sequential-XOR refusal) but not from above — an explicit
  `format_version=15` passed every `>= 14` gate, derived a real key, and
  stamped the unknown version into the metadata; the decrypt side then
  failed closed on it, leaving a permanently unreadable file (data-loss
  footgun for API callers) carrying an on-disk version whose semantics
  were never specified. New writes now raise a clear `ValueError` for
  `format_version > LATEST_STABLE_FORMAT_VERSION`, before any archiving
  or temp files, mirroring the decrypt-side bound. Not attacker-
  exploitable; no change for any valid version.

- **Remote and combined KDF pepper are now zeroized after use** (v14
  follow-up review LOW-1, gitlab#113, 2026-07-11): the v14 work wipes the
  TLV KDF seed in a `finally` block, but the pepper material feeding it
  outlived that wipe — the remote pepper (AES-GCM decrypt output) and the
  combined `hsm_pepper + remote_pepper` concatenation were immutable
  `bytes` that were never zeroized, and the existing `hsm_pepper` wipe was
  a no-op copy-zero on plugin-supplied `bytes` (M10). All three are now
  held in wipeable `bytearray` buffers from creation — the combined pepper
  is built by a new `_combine_peppers` helper in one exact-size allocation
  (no intermediate concatenation copies, same M2 [MEM-1] standard as the
  seed encoder) — and zeroized in the `encrypt_file`/`decrypt_file`
  `finally` blocks on all paths. Unavoidable immutable transients from
  library/plugin APIs (`AESGCM.decrypt` output, the plugin result dict)
  remain documented accepted residuals. No derived keys or file formats
  change; pure memory-hygiene hardening.

- **Recipient password wrap now binds the KEM ciphertext and algorithm
  into the key derivation (wrap_version 3)** (post-v14 review LOW-3,
  gitlab#112, 2026-07-11): `PasswordWrapper` derived the per-recipient
  AES-256-GCM wrap key from the ML-KEM shared secret with a static HKDF
  info — the finding-#83 transcript binding covered only the main PQC data
  path. New asymmetric files wrap with
  `info = "openssl_encrypt.password_wrap.v3|" + kem_algorithm + "|ct=" +
  SHA256(encapsulated_key)` and record `wrap_version: 3` in the recipient
  entry (inside the signed metadata). Defense-in-depth: ML-KEM implicit
  rejection plus the GCM tag already defeat ciphertext substitution in
  practice. Fail-closed by construction — a marked entry never falls back
  to weaker derivations, stripping the marker derives the wrong key and
  fails the tag, and unknown marker values are rejected. **Every existing
  file keeps decrypting** (entries without the marker take the previous
  v2→v1 chain byte-for-byte, pinned by a pre-fix fixture file); note that
  asymmetric files written from this version on cannot be opened by older
  releases (clean unwrap error — same trade as the v14 default flip).

- **Keystore metadata version gates are now type-safe** (post-v14 review
  LOW-2, gitlab#111, 2026-07-11): the keystore integration read
  `format_version` from raw parsed JSON and compared it with `>=`, so a
  crafted file carrying a non-int value (`"4"`, `true`, `[]`) crashed the
  operation with an unhandled TypeError. Fail-closed either way (no
  bypass, key material never touched), but a crash is a one-operation DoS
  and an ugly failure mode. All six affected ingestion points in
  `keystore_wrapper.py`/`keystore_utils.py` now validate the type once via
  a shared helper and reject malformed metadata with the project's clean
  `ValidationError`. Legitimately written files always store an int —
  behavior for every valid file is unchanged.

- **v14 TLV KDF seed is built in a single allocation** (post-v14 review
  LOW-1, gitlab#110, 2026-07-11): `_v14_seed_encode` previously grew its
  buffer with incremental `bytearray +=`, so CPython reallocations could
  leave partial copies of the length-prefixed cleartext password in freed,
  unwiped heap memory — the caller's `secure_memzero` wipes only the final
  allocation — and its `bytes()` field conversion would materialize an
  unwipeable immutable copy of a mutable (bytearray/SecureBytes) secret.
  The seed is now written into one exact-size preallocated bytearray
  through memoryviews: no reallocation, no immutable copies (M2 [MEM-1]
  hygiene). Not exploitable on its own — hardening only; derived keys and
  the on-disk format are byte-identical, pinned by the cross-line golden
  vectors plus a new byte-identity test matrix covering mutable inputs.

- **format_version 14 is now the default write format — independent-XOR
  topology by default** (finding M2 Option A / M1, v14 implementation plan
  Phase 4, 2026-07-10): new encryptions without an explicit format version
  (CLI and library) now write `format_version 14` with independent-XOR key
  derivation — the parallel robust-combiner topology that stays as strong as
  its strongest component even if another KDF stage is broken — replacing
  the plain sequential cascade default (weakest-link floor per the KDF-chain
  research). Explicit sequential XOR (`--use-xor-composition`) stays a
  supported opt-in pinned at format_version 13; explicit format-version
  requests are honored unchanged. Streaming now writes v14 too (so streaming
  PQC files carry the #83 transcript binding); explicit v12 requests keep
  writing v12 and all v12 files keep decrypting. M1 is closed by
  construction: the independent scrypt component derives the full key length
  (64/128-byte keys for AES-SIV/Threefish are no longer funneled through a
  256-bit sequential intermediate on any v14 write path) — pinned by golden
  vectors, with a legacy vector guarding that the `< 14` sequential scrypt
  stage stays byte-identical. Rekey with `--independent-xor` targets v14;
  a plain rekey inherits the file's format version and normalizes the
  topology to independent-XOR (the recommended mode — the rekeyed file is
  self-consistent and gets a fresh key, so nothing breaks). All existing
  files decrypt unchanged (decrypt is metadata-driven).

- **format_version 14: KEM ciphertext transcript binding** (finding #83,
  v14 implementation plan Phase 3, 2026-07-10): for v12/v13 the PQC KEM
  symmetric key is HKDF(shared_secret) with only the algorithm name as
  domain separation — nothing binds the derived key to the KEM encapsulation
  ciphertext or the AEAD choice. At `format_version >= 14` the derivation
  binds the full transcript:
  `HKDF-SHA256(info = "openssl_encrypt.kem.v14|" + algorithm + "|" +
  encryption_data + "|ct=" + sha256(kem_ciphertext))` (info layout pinned
  for cross-line byte-identity). A missing ciphertext at v14 raises — no
  silent fallback. The Phase 0 legacy bare-SHA256 decrypt retry is now
  scoped to v12/v13 only (no v14 file can carry a legacy key, so v14 fails
  after a single authenticated attempt). v12/v13 derivations are
  byte-identical to before (Phase 0 goldens unchanged).

- **format_version 14: length-prefixed (TLV) KDF seed** (finding #100,
  v14 implementation plan Phase 2, 2026-07-10): below v14 the
  independent-XOR key derivation seeds every component from
  `sha256(password || pepper || salt)` with the hardware pepper mixed by raw
  concatenation — so different (password, pepper, salt) splits of the same
  byte string derive the same key (boundary ambiguity; rated impractical to
  exploit since tool-generated salts have fixed length, but structurally
  unsound). Files at `format_version >= 14` seed from
  `sha256(LP(password) || LP(salt) || LP(pepper))` with
  `LP(x) = uint32_be(len(x)) || x` and an always-present pepper field
  (`_v14_seed_encode`, pinned for cross-line byte-identity). Everything
  below v14 derives byte-identically to before (v13/v11 golden vectors
  unchanged); nothing writes v14 by default yet. Verified during
  implementation: the spec's other #100 sites (the `multi_hash_password`
  seed concat and the 11 per-round `sha256(salt+i)` sites) are unreachable
  at v14 — the former is sequential-path only, the latter are `< 7` legacy
  branches — so the fix lands precisely at the one live site.

- **v14 TLV seed hashed without an immutable copy** (crypto-reviewer v14
  series pass 2026-07-10, Low): the v14 TLV seed is now hashed through a
  `memoryview` of the seed `bytearray` instead of an immutable `bytes()`
  copy, so no unwipeable copy of the cleartext password+salt+pepper is
  materialized (M2 [MEM-1] hygiene; derived keys are byte-identical —
  pinned by the cross-line golden vectors).

- **v14 KEM transcript binding: detection mechanism documented**
  (crypto-reviewer v14 series pass 2026-07-10, Low): `_derive_symmetric_key`
  now documents that the #83 transcript binding detects ciphertext/metadata
  substitution *via AEAD authentication* (wrong key → tag failure), not an
  explicit compare — so the binding requires the symmetric layer to remain
  an AEAD (all reachable PQC data ciphers are AEADs: AES-GCM/-GCM-SIV/-SIV/
  -OCB3 and ChaCha20/XChaCha20-Poly1305), guarding against a future
  non-authenticated data cipher silently voiding it.

- **Cross-line PQC KEM key-derivation compatibility** (finding #83 backport,
  v14 implementation plan Phase 0, 2026-07-10): the 1.4.x line derived every
  PQC KEM symmetric key as bare `sha256(shared_secret)`, while 1.5.x derives
  it via HKDF-SHA256 with algorithm-name domain separation for
  `format_version >= 12` — so v12 (streaming) and v13 (Independent-XOR) PQC
  files could not be decrypted across the two maintenance lines (confirmed
  empirically: 1.5.x-style decryption of a 1.4.x-written v13 PQC file fails
  with InvalidTag). `PQCipher` now implements the same `format_version`-gated
  HKDF derivation (`_derive_symmetric_key`), threaded from
  `encrypt_file`/`decrypt_file`, making new v12+ PQC files byte-compatible
  with 1.5.x. Files written by 1.4.x releases <= 1.4.7 with the legacy
  derivation **remain fully decryptable**: when HKDF-key authentication fails
  on a v12+ PQC file, decryption retries once with the legacy key (safe — the
  AEAD tag rejects wrong keys, and the legacy file population legitimately
  exists, so no new downgrade surface is introduced) and prints a
  re-encryption recommendation. Files below v12 and all non-PQC files derive
  byte-identically to before.

Follow-up security review (2026-07-07) — findings fixed with regression tests
and crypto-reviewer sign-off:

- **FIDO2/HSM pepper no longer printed in cleartext** (follow-up review #H1
  [HSM-1]): the `hsm fido2-test` command printed the full 32-byte derived
  hardware pepper as hex to stdout unconditionally — outside the
  `debug_secret()` redaction chokepoint, so it landed in scrollback/`script`/CI
  logs. The hex dump is removed (the length is still reported); the FIDO2 plugin
  already routed the pepper through `debug_secret()`, so this only closed a CLI
  inconsistency. *Note: this fix landed in `modules/hsm_cli.py`, which turned
  out not to be the frontend the `hsm` subcommand actually dispatches to — the
  reachable handlers were fixed under gitlab#121 (see the Security section
  above), so both frontends are clean as of this release.*
- **Plugin signature now covers the exact bytes that execute** (follow-up review
  #M1 [PLUGIN-2]): the loader verified a plugin's signature over one read while
  AST-scanning and executing others (verify-A / execute-B), and `exec_module`
  could run a cached `.pyc` never covered by the signature. `_validate_plugin_file`
  now reads the plugin once as raw bytes and threads that same buffer through the
  signature gate, the `sha256(raw)` pin, and `ast.parse(raw)`; `load_plugin`
  re-reads once, compares to the pin, and executes via `compile(raw)+exec` —
  killing the CRLF/BOM and `.pyc`-shadow discrepancies. Fail-closed on a missing
  pin for non-built-ins.
- **Signed per-package plugin manifest closes the sibling-coverage gap**
  (follow-up review #H2 [PLUGIN-1]): a package plugin's signed `__init__.py`
  transitively imported sibling modules that were never signature/AST/hash-checked,
  so a benign signed `__init__.py` plus a malicious unsigned `helper.py` executed
  unchecked. A signed `PLUGIN.manifest` now covers **every** importable module
  under the package (source `.py`, bytecode `.pyc`, native `.so`/`.pyd`,
  recursively incl. underscore/nested) with one detached `.asc`; under `enforce`
  a tampered/unlisted/native-swapped/impostor-signed sibling is refused, `warn`
  warns and loads, built-in packages keep the trust shortcut. `plugin sign`
  auto-detects a package and writes the manifest. (A runtime import-hook for the
  validation→import TOCTOU window remains a documented follow-on.)
- **Key material is now actually wiped at plugin/KDF call sites** (follow-up
  review #M2 [MEM-1]): several callers wrapped an immutable `bytes` secret in
  `bytearray(...)` and called `secure_memzero` on the throwaway copy — zeroing a
  copy while the real secret lingered in unlocked heap (the exact M10 anti-pattern,
  reintroduced at callers in `parallel_kdf.py`, `asymmetric_core.py`, `pqc.py`,
  `crypt_core.py`). Each secret is now held in a `bytearray`/`SecureBytes` from
  creation and that object is wiped.
- **Parallel and sequential Independent-XOR now derive the same key** (follow-up
  review #M3 [KDF-1]): for Argon2 with `rounds > 1` the parallel KDF path and the
  sequential path produced different keys, so a file encrypted under one and
  decrypted under the other failed to authenticate. The parallel worker now
  matches the sequential derivation exactly.
- **RandomX now fails closed in the parallel Independent-XOR path** (follow-up
  review #R1 [KDF-2b]): a RandomX failure in the parallel path was swallowed and
  the derivation continued (fail-open), unlike the sequential path which fails
  closed. Both paths now fail closed.
- **Streaming per-chunk AEAD auth failures classified structurally** (follow-up
  review #M4 [STREAM-1]): a per-chunk authentication failure during streaming
  decryption was detected by substring-matching the exception text, which could
  misclassify an integrity failure. Classification is now structural.

- **Debug logs no longer leak a KDF key intermediate** (audit 2026-07-06 #2):
  the per-round Argon2/Balloon/Scrypt debug lines printed `round_salt` as raw
  hex, and for `format_version >= 7` rounds ≥ 1 that "salt" is the first 128 bits
  of the live derived-key chain. Under plain `--debug` this leaked key material
  outside the `debug_secret()` redaction chokepoint; it is now redacted by
  default (cleartext only under `--debug --unsafe-show-secrets`).
- **New files are no longer written in the cost-bypassing v8/v10 format** (audit
  2026-07-06 #3): the v8/v10 sequential-XOR derivation appended the chain's final
  value twice, cancelling the last KDF stage so an Argon2-only config collapsed
  to ~`SHA256(password‖salt)`. `encrypt_file` now defaults to `format_version=9`
  (the secure chained-salt format, matching the CLI and `generate_key`) and
  **refuses to encrypt** new v8/v10 files (decryption of existing v8/v10 files is
  unaffected; a library-only `allow_insecure_legacy_xor` escape hatch exists for
  legacy-fixture tests). `rekey` transparently upgrades an inherited v8/v10 file
  to v9 — including the envelope fast-path, which no longer re-emits a legacy
  file verbatim — so rekey is a real migration off the weak derivation. A
  pytest-only PBKDF2 injection that had zero production effect but broke default
  round-trips and v7≡v9 equivalence was removed. The envelope rekey fast-path
  now accepts every version envelope writes (v9/v11/v12/v13), and the v9 metadata
  schema now lists the ML-KEM/Kyber hybrid algorithms it legitimately produces.

### Fixed

- **`string_entropy` Unicode handling**: non-ASCII characters (accented letters,
  other scripts, emoji) were excluded from the unique-character count and could
  score a password at 0.0 bits. They now contribute to the estimate, and the
  misleading "constant-time" claim in the docstring was corrected. ASCII scores
  are unchanged. (Backported from 1.5.x.)

## [1.4.7] - 2026-06-29

### Changed

- **Documentation / packaging release.** Updated `README.md` (which is rendered as
  the PyPI project page) for the 1.4.6 feature set: refreshed the "What's New" and
  release-history sections, and corrected the "KDF Composition Modes" section, which
  still described Independent XOR v11 as the default and pointed at a superseded TODO
  — it now documents format version 13 (per-component domain-separated salts) as the
  default and notes the sequential-XOR KDF-cost fix (ADVISORY 2026-02) as shipped. No
  functional or on-disk format changes; published to refresh the PyPI project page
  (PyPI artifacts are immutable, so the README fix required a new version).

## [1.4.6] - 2026-06-29

### Added

- **Format version 13 — Independent XOR with per-component domain-separated
  salts** (now the **default** for Independent XOR; non-breaking): the Independent
  XOR key derivation (v11) fed every hash/KDF component the *same* `salt_0`, so two
  components that were the same function with identical parameters could XOR to
  zero (cancellation). v13 derives a distinct
  `HKDF-SHA256(salt_0, info="openssl_encrypt.indep-xor.v13.salt:" + name)` salt per
  component, retiring the footgun while keeping the robust-combiner (strongest-link)
  guarantee. **`--independent-xor`, the STANDARD/PARANOID templates, and rekey now
  write v13**; v11 remains fully supported for **decryption** (append-only). Files
  `< 13` decrypt unchanged; v13 is byte-identical across the 1.4.x and 1.5.x lines
  (pinned by a cross-line golden vector). v13 uses the sequential derivation, so
  `--parallel-kdf` falls back to sequential for v13 (with a notice).
- **Sequential XOR last-stage cancellation fixed (KDF cost bypass)** — ADVISORY
  2026-02: in sequential XOR (`--xor`, `format_version 8`/`10`) the chain's final
  value was XOR'd into the key *in addition to* the last stage's own snapshot,
  which are equal — so they cancelled and the **last stage dropped out of the
  key**. For Argon2-only (Argon2 is last) the key reduced to the cheap **initial**
  `SHA256(pw+salt)` computed before the chain (the original password/salt, not the
  derived values), bypassing the configured Argon2 cost. `--xor` now writes
  **format_version 13** (`xor_mode: "sequential"`) with the redundant append
  removed, so every stage contributes. Existing v8/v10 files still decrypt
  (derivation preserved) but are weak until re-encrypted. v13 routes XOR mode by
  the on-disk `xor_mode` field (independent vs sequential), not the version.
- **Hidden ("whitened") file format** (`--hidden-header`, opt-in; ported from
  the 1.5.x line): wraps the encrypted output in an outer layer so the whole
  file is indistinguishable from random bytes, hiding the identifiable
  `base64(metadata):base64(body)` header that fingerprints a file as ours and
  leaks the derivation profile. Only the small metadata header is whitened; the
  body is kept raw (no double-encryption), preserving streaming and bounded
  memory. Two modes share one byte-identical layout (so the presence of a
  second password is not observable): **keyless** (outer key from the *public*
  salt — anti-fingerprinting only, reversible by anyone with the tool) and
  **keyed** (`--second-password…` → fixed heavy chain 100k×SHA3-512 →
  5×Argon2id → scrypt → HKDF, giving real metadata confidentiality even against
  an analyst who has the tool). Supported on the symmetric, keystore-wrapped,
  and asymmetric (PQC) paths, buffered and streaming. Decryption auto-detects
  legacy vs hidden (no magic bytes); `--legacy-format` forces legacy. On
  decrypt, a keyed file with a missing/wrong second password fails with the same
  generic error as any wrong/corrupt input (no oracle); an **interactive,
  TTY-gated second-password prompt** offers it before failing (suppressible with
  `--no-second-password-prompt`, never fires in scripts). **Purely additive and
  backward-compatible** — without `--hidden-header` the output is byte-for-byte
  the legacy format. See `docs/HIDDEN_HEADER.md`.

- **Recovery slots** (envelope add-on, ported from the 1.5.x line): an envelope
  file's Data Encryption Key can be wrapped under one or more *independent*
  recovery credentials in addition to the password, so losing the password no
  longer means losing the data. Three credential types on this line: a
  generated high-entropy **recovery code** (HKDF), a memorable **recovery
  passphrase** (Argon2id), and a **PQC escrow recipient** (ML-KEM public key,
  API only). (Shamir k-of-n is intentionally not ported here — the
  secret-sharing module is 1.5.x-only.) Decryption succeeds with the password
  *or* any recovery credential. The recovery-slot SET is bound by a DEK-keyed
  MAC (`encryption.dek_slots_mac`), verified on every decryption path, so
  stripping/injecting/modifying/swapping slots fails closed; the slot fields are
  excluded from the bulk AEAD AAD so slots can be added/removed post-hoc without
  re-encrypting the bulk. **Purely additive and fully backward-compatible**:
  files without recovery slots are byte-identical. CLI: `add-recovery`,
  `remove-recovery`, `list-recovery`, `recover`. On-disk format pinned by
  committed golden fixtures (`testfiles/recovery_slots/`). See
  `docs/RECOVERY_SLOTS.md`.

- **Real 192-bit XChaCha20-Poly1305 nonces** (spec-compliant per
  draft-irtf-cfrg-xchacha-03), backported from the 1.5.x line. Replaces the
  previous behavior where a 24-byte nonce was stored but only the first 12
  bytes affected the keystream (96-bit effective — not a vulnerability thanks
  to per-file keys, but not real XChaCha and not interoperable):
  - New module `modules/xchacha.py` implements HChaCha20 on top of the
    `cryptography` library's ChaCha20 (keystream feed-forward subtraction) —
    no new runtime dependency. Pinned against the official §2.2.1 and §A.3
    test vectors and an independent pure-Python reference
    (`test_xchacha_primitives.py`).
  - New files carry `encryption.xchacha_nonce_format: 2` in their metadata,
    set before the AEAD binding so the flag is authenticated (stripping or
    downgrading it fails decryption). Applies to one-shot, cascade, and
    streaming (24-byte per-chunk nonces).
  - **Fully backward compatible**: every pre-backport file (no flag) keeps
    decrypting through its historical path — one-shot/streaming use the first
    12 bytes; cascade uses the HKDF nonce funnel. Pinned by immutable fixtures
    (`testfiles/xchacha_legacy/`); the new format is pinned by
    `testfiles/xchacha_v2/`, which also confirms files written by the 1.5.x
    line decrypt here (cross-version interop). This includes envelope files
    whose cascade chain contains XChaCha: the wrapped-DEK layer uses the same
    real 192-bit construction as the bulk (honoring the metadata flag on
    unwrap and rekey), so envelope + cascade + XChaCha is fully interoperable
    across both lines — pinned by the genuine legacy fixture
    `testfiles/envelope_xchacha_v14/`, which still decrypts unchanged.
  - The PQC hybrid data layer intentionally keeps 12-byte nonces under
    per-encryption KEM-derived keys.

- **Envelope encryption (DEK/KEK)** (`--envelope`, opt-in): bulk data is
  encrypted under a random Data Encryption Key (DEK), and the DEK is wrapped by a
  Key Encryption Key derived from the password through the full, unchanged KDF
  chain. Decryption auto-detects envelope files. Enables **O(header) credential
  rekey** (rewrap the small DEK + rewrite the metadata header; the bulk
  ciphertext is retained verbatim — this rotates the *access credential*, not the
  data key, so a full re-encrypt remains available for true data-key rotation).
  The bulk AEAD binds a canonical stable subset of the metadata that excludes
  only the KEK-gating fields a rekey changes, so a rekey keeps the ciphertext
  valid while tampering any authenticated field still fails closed. For a
  `cascade` chain the DEK is wrapped under the *same* chain so the envelope is
  never the weak link. Opt-in and fully backward-compatible: non-envelope files
  are byte-for-byte unchanged; DEK/KEK are zeroed on every path and never logged.
  Foundation for future multi-password / multi-recipient wrapping. (Ported from
  the 1.5.x line; the wrapped-DEK format is interoperable across both lines,
  including XChaCha cascade chains once the real 192-bit nonce format is in
  use — see the XChaCha entry above.)

- **Detached file signing** (`sign` / `verify-signature`): post-quantum
  (ML-DSA-65) detached signatures over **arbitrary files**, closing the
  authenticity gap of symmetric AEAD (which gives confidentiality + integrity
  but lets anyone who knows the password forge a valid file).
  `sign --input F --sign-with IDENTITY` writes a `.sig` JSON sidecar
  (ASCII-armored by default; `--no-armor` for raw) that binds the file's
  SHA-512 digest to the signer over a domain-separated payload (distinct from
  the encrypted-file metadata signature). `verify-signature` resolves the
  signer's public key from your identity store **and contacts** by the embedded
  fingerprint, **fails closed on an unknown signer** (`--signer` to pin),
  reports which signature component(s) verified, and supports `--json`. The
  sidecar's `signatures` list is forward-compatible with a future classical
  (e.g. Ed25519) hybrid component. New module
  `openssl_encrypt/modules/file_signature.py` (covered by the signed manifest).

- **ASCII armor** (`encrypt --armor` / `-a`): write PEM-style Base64 output that
  is safe to paste into email, chat, YAML or a clipboard. The whole encrypted
  blob is wrapped in a `-----BEGIN/END OPENSSL-ENCRYPT MESSAGE-----` envelope
  with an OpenPGP-style CRC-24 checksum that detects paste truncation/corruption
  (fails closed on malformed armor). `decrypt`, `info` and `verify` auto-detect
  armored input by content — no flag required — and the round-trip is byte-exact.
  Works across the symmetric, `stdin`→`stdout` streaming, and recipient
  (asymmetric) output paths. New module `openssl_encrypt/modules/armor.py`
  (covered by the signed integrity manifest).

- **Encrypt-to-self** (`encrypt --for-identity …`, on by default): when
  encrypting *for* recipients, the sender's own identity (`--sign-with`) is now
  added as an additional recipient so the sender can later decrypt their own
  outbound file — removing a common data-loss footgun. The sender slot reuses
  the existing multi-recipient ML-KEM wrapping and is de-duplicated by
  fingerprint. Opt out with `--no-encrypt-to-self`.

- **PIV / PKCS#11 HSM backend** (`--hsm piv`): hardware-bound key derivation
  backed by a PIV private key on a PKCS#11 token (YubiKey Bio MPE, Token2 PIN+
  R3.3+, or any compliant PIV smart card). The key signs a deterministic
  challenge derived from the salt and the signature is normalized into a pepper
  via HKDF-SHA256. Algorithm-agnostic across Ed25519 and RSA-2048/3072/4096;
  non-deterministic schemes (ECDSA, RSA-PSS) are explicitly rejected so the
  same key on multiple devices always yields identical peppers.
  - New flags: `--hsm-pkcs11-lib PATH` (required), `--hsm-piv-slot {9a,9c,9d,9e}`,
    `--hsm-biometric`; `--hsm-slot` selects the PKCS#11 slot index for PIV.
  - PIN is read via `getpass` (never via CLI args/logs/exceptions), held in a
    `bytearray`, and zeroed after login; a final-try guard refuses lock-risking
    attempts without confirmation; sessions are closed on every exit path.
  - New dependency: `python-pkcs11` (in `requirements-hsm.txt`).
  - Setup guide: `openssl_encrypt/docs/PIV_BACKEND.md`.

- **Source-code integrity protection** (`openssl-encrypt verify-integrity`): a
  PGP-signed manifest of SHA-512 hashes over the core cryptographic/security
  source files (the explicit allowlist in
  `openssl_encrypt/integrity/protected_files.txt`) so tampering with those files
  can be detected. Both a source-scope and an installed-scope manifest are
  maintained and shipped in the package; a pre-commit hook regenerates and checks
  for drift. The bundled verifier is a convenience tripwire — authoritative
  verification is manual with a trusted `gpg` against the out-of-band signing
  fingerprint `D269D6A5D6D7CE52CE1FC71DC2DF29059ED65043` (also published in
  `SECURITY.md`). Signing key rotated from the bootstrap key to the production
  key. Runbook: `openssl_encrypt/docs/SOURCE_INTEGRITY.md`.

### Fixed

- **Streaming files could not be decrypted** (full-pipeline `encrypt` → `decrypt`
  via the streaming path). A streamed file records `format_version 12` in its
  metadata, and decryption re-derives the password key from that stored version,
  but encryption derived the key at the original `format_version` (default 10)
  *before* the streaming decision was made — and the encrypt-side guard missed
  v12 — so the encrypt and decrypt keys diverged and every chunk failed
  authentication (`InvalidTag`). The streaming path now decides streaming and
  pins `format_version 12` **before** key derivation, matching decryption.
  Added full-pipeline regression coverage (`TestFullPipelineStreamingRoundtrip`)
  — the prior streaming tests used fixed keys and bypassed the key-derivation
  pipeline, which is why this went unnoticed. (Issue #50.)

## [1.4.5] - 2026-06-12

### Security

- **Dependency updates for published CVEs** (all patched versions verified
  clean against OSV; production and dev pin sets now audit clean):
  - `urllib3` 2.6.3 → 2.7.0 — CVE-2026-44431 (sensitive headers forwarded
    across origins in proxied low-level redirects), CVE-2026-44432
    (decompression-bomb safeguard bypass in the streaming API)
  - `cryptography` 46.0.6 → 46.0.7 — CVE-2026-39892 (buffer overflow with
    non-contiguous Python buffers in APIs like `Hash.update()`)
  - `pillow` 12.1.1 → 12.2.0 — integer-overflow bypass of the PSD
    tile-extent bounds checks (follow-up to CVE-2026-25990)
  - `idna` 3.11 → 3.15 — incomplete-fix follow-up to CVE-2024-3651
  - dev-only: `authlib` → 1.6.12 (CVE-2026-41425, CVE-2026-41479,
    CVE-2026-44681), `pygments` → 2.20.0 (CVE-2026-4539),
    `pytest` → 9.0.3 (CVE-2025-71176)

### Internal

- **New `flatpak-pin-check` CI job + consistency test**: the flatpak
  manifest's hard-coded pip pins are now verified against
  `requirements-prod.txt` on every push (including feature branches).
  The check immediately caught and fixed a stale `requests` pin in the
  manifest.
- Flatpak manifest dependency pins aligned with requirements-prod.txt.

## [1.4.4] - 2026-06-12

### Added

- **Cross-device HSM decryption (YubiKey ↔ OnlyKey)**: files encrypted with
  one HMAC-SHA1 challenge-response device can now be decrypted with the
  other by selecting it explicitly via `--hsm`, provided both devices hold
  the same 20-byte secret (`yubikey_hsm` / `onlykey_hsm` form a
  protocol-compatible plugin family; unrelated plugins are still rejected).
  `--hsm-slot` on `decrypt` / rekey now takes precedence over the slot
  stored in file metadata — previously it was printed but silently
  ignored — so fleet devices may hold the secret in different slots.
- **OnlyKey setup guide** (`docs/ONLYKEY_SETUP.md`, linked from the docs
  sidebar): installation, udev rules for VID/PID 1d50:60fc, the
  unlock-then-touch hardware flow, the challenge-code-mode caveat,
  cross-device provisioning with YubiKey, and troubleshooting for every
  real-hardware failure mode.
- **`info` action now reconstructs the `encrypt` CLI** from file metadata:
  - The human-readable output of `openssl_encrypt info <file>` now ends
    with a "Reconstructed CLI" section showing the full
    `openssl_encrypt encrypt ...` command that would produce equivalent
    encryption settings on a fresh file.
  - Salt and per-file random values are NOT reconstructed — only the
    deterministic configuration (cipher / cascade chain, all five KDFs
    Argon2id/scrypt/Balloon/HKDF/RandomX, the 12 hash-rounds flags,
    legacy PBKDF2 / Whirlpool flags, HSM binding via `--hsm` +
    `--hsm-slot`, remote-pepper plugin via `--pepper` + `--pepper-name`).
  - JSON output mode (`info --json`) is unchanged — the JSON payload
    remains the raw metadata dict, so scripts piping into `jq` continue
    to work without modification.
  - Round-trip property covered by automated test
    (`test_info_reconstruction.py::TestReconstructionRoundTrip`):
    encrypting a fresh file with parameters X, extracting metadata, and
    running the reconstructor yields a CLI flag string containing
    every parameter value from X.
  - Argon2's `type` field is auto-converted from the on-disk integer
    representation (0/1/2) back to the CLI form (`d`/`i`/`id`).
  - SHA-3 hash names use the metadata form (`sha3_512`) translated to
    the CLI flag form (`--sha3-512-rounds`).
- **`derive-password` gains HSM-aware deterministic derivation**:
  - `--hsm yubikey` / `--hsm onlykey` (+ optional `--hsm-slot`) plumb
    the hardware token's HMAC-SHA1 response into the KDF cascade. Same
    password + same salt + same device-loaded secret = same output;
    re-provisioning the device silently changes the output.
  - When `--hsm` is set without explicit `--salt` (random-salt mode), a
    stderr reminder fires explaining the three reproducibility inputs
    (password, salt, hardware secret) so users don't get surprised when
    re-running fails.
  - `--confirm` prompts for the password twice and rejects on mismatch
    — guards against typos that would silently produce a wrong derived
    value. No-op when password comes from `--password` / `--password-file`
    / `--password-fd` / `OPENSSL_ENCRYPT_PASSWORD` / `--keyring-load`.
- **Diceware passphrase generation** for `generate-password`:
  - `--dice` switches `generate-password` from character-based generation
    to a Diceware-style passphrase (mutually exclusive with the
    `--use-lowercase/uppercase/digits/special` flags).
  - `--dice-count N` (default 10) — number of words. Defaults to 10 for a
    conservative ~129 bits of entropy with the bundled EFF list.
  - `--dice-sep SEP` (default `""`) — separator between words. Defaults to
    empty for maximum compatibility with password fields that strip
    whitespace.
  - `--dice-list PATH` — custom wordlist; auto-detects EFF format
    (`<dice>\t<word>`) vs plain one-word-per-line.
  - `--force-wordlist` — override the 1024-word (10 bits/word) minimum
    for custom wordlists. Default rejects undersized lists outright;
    forcing emits a UserWarning but proceeds.
  - The bundled
    [EFF Large Wordlist](https://www.eff.org/dice) (7,776 words) ships
    at `openssl_encrypt/data/eff_large_wordlist.txt` under
    [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/);
    attribution lives in `openssl_encrypt/data/EFF_WORDLIST_LICENSE.txt`.
  - Diceware mode prints `Passphrase entropy: X bits (N words)` to
    stderr, then the passphrase via the existing display helper.
  - Wordlist loader strict-validates: rejects duplicate words and
    words containing whitespace (both would silently corrupt entropy
    or boundary semantics).
  - Policy interaction: in `--dice` mode only entropy- and length-based
    policy checks apply; character-class and common-password checks are
    skipped (they are orthogonal to passphrase security).
- **OnlyKey Challenge-Response HSM plugin**: New `OnlykeyHSMPlugin`
  (`openssl_encrypt/plugins/hsm/onlykey_challenge_response/`) adds
  hardware-bound pepper derivation via OnlyKey devices (USB VID/PID
  `0x1d50:0x60fc`) using the same HMAC-SHA1 wire protocol as YubiKey.
  CLI: `--hsm onlykey` for encrypt/decrypt, slots 1..12 via `--hsm-slot`,
  auto-detected if omitted. Two new HSM management subcommands:
  `openssl_encrypt hsm onlykey-list` and `openssl_encrypt hsm onlykey-test`.
- **OnlyKey identity protection**: `openssl_encrypt identity create`
  now accepts `--hsm onlykey` and `--hsm onlykey-only` alongside the
  existing yubikey options. `IdentityKeyProtectionService` selects the
  plugin via a new `hsm_type` constructor argument; the type is
  serialised into the identity protection metadata so decrypt routes
  to the correct plugin.
- **Cross-device deterministic pepper guarantee**: A YubiKey and an
  OnlyKey loaded with the same 20-byte HMAC-SHA1 secret produce
  identical responses for identical challenges, allowing mixed fleets.
  Verified by a new RFC 2202 parameterised determinism test
  (`test_cr_cross_backend_determinism.py`).
- **Documentation**: `docs/hardware-tokens.md` (combined YubiKey +
  OnlyKey setup guide, fleet provisioning workflow, troubleshooting)
  and `docs/migration-from-yubikey-only.md` (step-by-step for existing
  users adding OnlyKey to their fleet).
- **Regression test baseline for YubikeyHSMPlugin**
  (`test_yubikey_plugin.py`, 24 tests) — locks in existing behaviour
  prior to the OnlyKey work.

### Changed

- **Declared Python floor raised to `>=3.11`** in `setup.py` and
  `threefish_native/pyproject.toml` (the pinned dependency set already
  required it — numpy 2.3 needs >=3.11 — so 3.9/3.10 installs failed at
  dependency resolution anyway). Stale 3.9/3.10 classifiers dropped,
  3.14 added. Guarded by `test_python_floor_metadata.py`.
- `--hsm-slot` no longer hard-restricted to `choices=[1, 2]` at the
  argparse layer. YubiKey validates 1..2 inside its plugin; OnlyKey
  validates 1..12. This is purely an internal validation move — no
  user-visible behaviour change for existing YubiKey users; OnlyKey
  users can now select any slot in 1..12.
- `handle_hsm_command` no longer imports / requires FIDO2 unconditionally.
  The fido2 availability gate is now scoped to `fido2-*` actions only,
  so `onlykey-list` / `onlykey-test` work on machines without fido2.

### Fixed

- **OnlyKey plugin now works with real hardware**: device construction no
  longer fails with "24828 is not a valid PID" — the plugin masquerades as
  an OTP-only YubiKey (`PID.YKS_OTP`), since yubikit's PID enum only
  contains Yubico product IDs and the PID is used solely for USB interface
  bookkeeping. `open_connection` is now called with `OtpConnection`
  instead of `None` (ykman asserts on non-type arguments). A device that
  actively rejects a challenge now produces an actionable error naming the
  two real-world causes (empty slot / challenge-code mode) instead of the
  bare "No data".
- **threefish_native builds on Python 3.14**: PyO3 upgraded 0.24.1 → 0.26
  (3.14 support), with the `PyBytes::new_bound` → `PyBytes::new` API
  rename.
- **ML-KEM hybrid encryption via the CLI was impossible with any
  spelling**: the `ml_kem_patch` compatibility shim rewrites
  `--algorithm ml-kem-*-hybrid` to the legacy `kyber*-hybrid` names
  before argument handling, and the v1.2.0 deprecation gate then
  rejected the converted name — telling users to "use ml-kem-768-hybrid"
  in response to them typing exactly that. The gate now judges the name
  the user actually typed; the legacy kyber names remain blocked for new
  encryptions. Also fixed a latent crash this unmasked on the subcommand
  path (missing `pqc_gen_key` attribute default). Regression-tested
  through the real CLI entry point
  (`test_mlkem_cli_regression.py`).

- **Undefined-name (F821) bugs**: `keystore_cli.py` used a `logger` that
  was never created (NameError on any code path that logged) and
  `versions.py` called `eprint` without importing it when executed as
  `__main__`. Both fixed during the lint campaign; two further F821s in
  test files (missing `shutil` import, missing `original_import`
  capture) repaired as well.

### Security

Security-review findings (SECURITY_REVIEW_FINDINGS.md) fixed on the 1.4.x
line. None of these change the on-disk encryption format — all existing
files remain decryptable.

- **Keystore integrity — authenticated v2 keystore format (H4)**: the
  keystore previously stored everything except wrapped private keys as
  cleartext, unauthenticated JSON, so anyone with write access could swap
  a stored public key, repoint per-algorithm defaults or delete entries
  undetected. v2 authenticates the entire structure with HMAC-SHA256 over
  canonical JSON, keyed by a domain-separated subkey of the master key;
  any mismatch fails closed with `KeystoreIntegrityError`. Legacy v1
  keystores load with a warning and auto-upgrade to v2 on the next save.
  A regression test proves the store-level MAC also neutralizes the
  blob-move attack (M6).
- **D-Bus per-caller authorization (H7+L8)**: EncryptFile/DecryptFile/
  SecureShredFile and the keystore methods previously performed no caller
  authorization — on the system bus any local user could drive a root
  service. Every state-touching method now authorizes the caller first
  and fails closed (missing sender, unresolvable UID or unreachable
  polkit ⇒ deny, audit-logged): session bus requires caller UID ==
  service UID; system bus (new explicit `--system` flag) checks polkit
  `CheckAuthorization` against the shipped action ids, now tightened to
  `auth_admin_keep` (any-user access to the root service is gone). Path
  policy is mode-aware: system mode whitelists root-only file purposes
  (`/etc/shadow`, `/boot`, `/proc` stay blocked), session mode remains
  home/tmp-only.
- **PQC algorithm resolution fails closed (H3)**: `PQCipher` no longer
  silently falls back to the weakest available KEM when a requested
  algorithm cannot be resolved (e.g. ML-KEM-1024 on a build lacking it,
  or a typo) — it raises `ValueError` listing the available algorithms.
  Legacy Kyber names still normalize to ML-KEM at the *same* security
  level.
- **Portable USB drives use a unique per-drive KDF salt (H5)**: master-key
  derivation previously used one global hardcoded salt for every drive,
  enabling a single precomputed dictionary against all drives. New drives
  generate a random 32-byte salt (`config/salt.bin`); pre-existing drives
  transparently fall back to the legacy salt and remain verifiable.
- **Plugin sandbox hardening (H8)**: file/network/process restrictions are
  now enforced on the default process-isolation path (previously only in
  legacy threading mode — a plugin without file capability could still
  read arbitrary files); the AST denylist closes the
  frame/traceback escape chain (`__traceback__` → `f_back` → `f_globals`);
  plugins in group/world-writable files or directories are rejected.
- **Balloon KDF memory-hard default (M3)**: on the v11 independent-XOR
  path an enabled Balloon with no explicit `space_cost` silently fell back
  to a ~512-byte buffer (GPU-trivial) and the value was not persisted.
  A memory-hard default is now applied and persisted at encrypt time;
  explicitly low values trigger a warning. Legacy files stay decryptable.
- **Weak dual-encryption password verifier removed (M7)**: dual-encrypted
  files no longer store a 10,000-iteration PBKDF2 hash of the file
  password in cleartext metadata (an offline brute-force oracle). The
  AES-GCM tag already authenticates the password; legacy files carrying
  the verifier are still honoured.
- **Identity TOFU key-change detection (M8)**: re-importing a contact
  whose key fingerprint changed now raises `IdentityKeyChangedError` even
  with `overwrite=True` (replacing a pinned key requires the explicit
  `allow_key_change=True`); fingerprint lookup now requires a full match
  instead of `startswith()` (an empty prefix used to resolve to the first
  stored identity).
- **Honest secure-memory contract (M10/M10a)**: `secure_memzero` no longer
  falsely reports success after zeroing a *copy* of immutable input — it
  returns `False` for `bytes`/`str` (new `strict=True` raises), and wipes
  in place for mutable buffers. The KDF registry password wipe, which
  never actually ran due to an always-false condition, is now effective
  and copy-free across all backends.
- **Metadata schema validation fails closed (M11)**: unknown
  `format_version` values are now rejected instead of skipping
  per-version schema validation; schemas are registered dynamically from
  disk (the shipped v9/v12 schemas were never registered and silently
  unused).

- No changes to the cryptographic core. The OnlyKey plugin reuses
  yubikit's `YubiOtpSession.calculate_hmac_sha1`; the only difference
  vs the YubiKey plugin is USB device enumeration (additional VID/PID
  filter). Existing YubiKey-encrypted files and YubiKey-protected
  identities are bit-identical and unaffected.

### Internal

- **Test-collection regression fixed**: `pytest.ini` (added 2025-12-30)
  silently stopped collecting `unittests/unittests.py` — 91 tests across
  12 classes had not run in any suite invocation since. Collection is
  restored and everything that surfaced was repaired, including a
  module-level `warnings.warn` monkeypatch that leaked into co-resident
  workers and broke later `pytest.warns()` assertions.
- New security-fix test suites: `test_keystore_integrity.py`,
  `test_dbus_authz.py`, `test_plugin_sandbox_h8.py`,
  `test_identity_tofu_m8.py`, `test_balloon_defaults_m3.py`,
  `test_kdf_wipe_m10a.py`, `test_secure_memzero_m10.py`,
  `test_metadata_schema_m11.py`, plus PQC fail-closed and per-drive-salt
  regression tests.
- **Code-quality campaign across the entire codebase**: black + isort
  formatting applied repo-wide, new `.flake8` config with
  per-file-ignores for test files, autoflake removal of unused imports
  and variables, 121 placeholder-less f-strings de-f-stringed (F541),
  bare `except:` replaced with `except Exception:` (E722/B001 — no
  longer swallows `SystemExit`/`KeyboardInterrupt`), redundant exception
  types removed (B014). The autoflake pass initially destroyed
  try/except optional-dependency import probes and `__init__.py`
  re-exports; both were restored and F401 is now suppressed globally to
  prevent a repeat.
- **Test robustness**: Whirlpool tests skip cleanly when the optional
  module is unavailable; stdout-leak whitelist updated after the
  formatting pass; rekey algorithm-change tests pinned against the
  STANDARD-template override.
- No new Python dependencies. The `onlykey` PyPI package is **not**
  required — HMAC-SHA1 is performed via yubikit (already pulled in
  via `yubikey-manager`).
- ~200 new unit tests across `test_onlykey_plugin.py`,
  `test_onlykey_cli.py`, `test_onlykey_identity_protection.py`,
  `test_cr_cross_backend_determinism.py`, and `test_yubikey_plugin.py`.

## [1.4.3] - 2026-03-30

### Fixed

- **Flutter GUI launcher in Flatpak**: Corrected binary name in wrapper script (`openssl_encrypt_mobile` → `openssl_encrypt`) so `--gui` flag works correctly
- **GTK window title**: Changed window title from `openssl_encrypt_mobile` to `OpenSSL Encrypt`

## [1.4.2] - 2026-03-29

### Added

- **Simple/Pro mode for desktop GUI**: New default "Simple" mode hides all advanced crypto options, showing only Encrypt, Decrypt, and Settings tabs. Uses CLI `--standard` template automatically. Pro mode toggle in Settings restores full UI with all algorithms, KDFs, cascade, steganography, and identity management
- **Independent XOR (v11) as default key derivation**: STANDARD and PARANOID templates now automatically enable Independent XOR composition (a robust XOR-combiner) for stronger key derivation security guarantees
- **RandomX support in independent XOR path**: RandomX KDF now works correctly in both parallel and non-parallel v11 key derivation paths
- **Progress bars for Argon2 and RandomX in XOR mode**: Multi-round KDF operations now display progress bars when using `--progress` flag in independent XOR (v11) mode

### Changed

- **STANDARD template modernized**: Hashes changed from sha3-256+sha3-512 to sha3-512+blake3 (10k rounds each). KDFs changed from scrypt+argon2 to randomx (10 rounds)+argon2 (10 rounds). Encryption upgraded from single-layer aes-gcm to cascade (aes-256-gcm + chacha20-poly1305)
- **Cascade encryption enabled by default**: STANDARD template now uses 2-layer cascade encryption (AES-256-GCM + ChaCha20-Poly1305) for defense-in-depth

### Security

- **Dependency bumps**: cryptography 46.0.5→46.0.6, requests 2.32.5→2.33.0, black 24.10.0→26.3.1, nltk 3.9.3→3.9.4

## [1.4.1rc2] - 2026-03-22

### Security

- **Dependency bump: nltk to 3.9.3**: Resolves CVE-2026-33236, CVE-2026-33231, CVE-2026-33230, GHSA-rf74-v2fm-23pw

## [1.4.1rc1] - 2026-03-21

### Added

- **Streaming chunked encryption (format v12)**: Large files now encrypted in authenticated chunks with configurable chunk size, enabling constant-memory operation, per-chunk integrity verification, and efficient handling of multi-gigabyte files
- **`--info` CLI action**: Display metadata about an encrypted file (format version, algorithms, `encrypted_at` timestamp) without decrypting
- **`encrypted_at` timestamp**: Metadata now records encryption time for auditing purposes
- **Windows compatibility**: Full Windows support backported from v1.5.x including NTFS ACL-based file permissions, UTF-8 encoding fixes across all file I/O, and an automated Whirlpool build step for Windows
- **Cross-platform `tty_write`/`tty_clear_line` helpers**: Interactive terminal prompts (YubiKey touch, password clear) now bypass stdout/stderr redirection by writing directly to `/dev/tty` on Unix or `msvcrt` on Windows, with emoji-safe fallback for Windows consoles
- **Stderr output separation**: All status, progress, and diagnostic output now goes to stderr via `eprint()`. Redirecting with `2>/dev/null` correctly suppresses all non-data output without affecting the decrypted content on stdout

### Security

- **Key zeroization in streaming/cascade/crypt_core**: All derived intermediate keys zeroed via `SecureBytes`/`secure_memzero` immediately after use
- **HKDF for keystore password wrap key**: Replaced bare SHA-256 with HKDF for deriving the keystore password wrap key
- **HKDF for recipient (asymmetric) password wrap key**: Replaced bare SHA-256 with HKDF-SHA256 (`password_wrap.v2`) for deriving the per-recipient AES-256-GCM key that wraps the bulk password under the ML-KEM shared secret; decryption falls back to the legacy bare-SHA256 (`v1`) derivation so existing recipient files still open
- **HKDF for streaming HMAC key** (v12+): Per-encryption HMAC key derived via HKDF rather than direct KDF output
- **Per-layer salt and AAD for cascade** (v12+): Each cascade layer receives an independently derived salt; all layers bound to the ciphertext via AAD (H6/H7/M12)
- **HKDF for pepper and PQC signature keys** (v12+): Pepper and PQC signature keys derived via HKDF with `format_version` wired through the derivation context (M15/M18/C2)
- **PQC signature HKDF salt pre-bound**: Salt generated before AEAD metadata construction, binding it into the ciphertext and preventing post-encryption metadata modification attacks
- **Per-chunk nonce bound into cascade**: Streaming chunk nonces passed to each cascade layer, preventing cross-chunk nonce reuse
- **Chunk count validation**: Streaming decryptor validates `chunk_count` from metadata against actual payload size, preventing truncation attacks
- **Format version integer validation**: `decrypt_file()` now rejects non-integer `format_version` values in metadata
- **Keystore Argon2id fallback warning**: User is warned when keystore falls back from Argon2id to PBKDF2
- **Plugin sandbox hardening**: Blocked `marshal` and `codecs` modules; blocked `__dict__`, `__func__`, `__self__` attribute access; added detection of string concatenation building dangerous names; added TOCTOU mitigation for plugin file validation; fixed TOCTOU race in symlink check; hardened AST analyzer against additional bypass vectors (PL-4/PL-5/PL-6/H8/H9/H10)
- **Plugin execution serialization**: Threading-mode plugins execute under a lock, preventing race conditions in concurrent usage
- **Algorithm registries frozen after init**: Algorithm registries are made immutable after initialization, preventing runtime tampering (M9/M13)
- **HSM pepper cache as bytearray**: Cached pepper stored as `bytearray` to allow effective memory zeroing
- **PQCKeystore context manager**: Added `close()` and `__exit__` to zero keys on teardown
- **Identity private key AAD binding**: Identity private key encryption now includes AAD for ciphertext binding
- **Identity import fingerprint verification**: Fingerprint verified on identity import to detect tampering; identity names validated against path traversal (M5/H1/H2)
- **Restrictive file permissions**: Keystore files set to `0o600`; pepper config directory `0o700`, pepper config file `0o600`; keystore dual encryption now includes AAD (M1/M20)
- **KeyStretch state reset**: Mutable class-level state reset at the start of each encrypt/decrypt operation to prevent cross-call state leakage
- **PluginResult sensitive key filtering**: Sensitive keys stripped in `PluginResult` constructor (M10)
- **PluginSecurityContext immutable capabilities**: `capabilities` stored as `frozenset` to prevent runtime mutation
- **HTTPS enforcement in keyserver**: `register()` enforces HTTPS for keyserver URL (PL-8)
- **Server secrets hardening**: Removed insecure default token secrets from server config (SV-2)
- **Dependency security**: Bumped `authlib` to 1.6.9, `python-jose` to 3.4.0, `cryptography` to ≥46.0.5

### Performance

- **Incremental metadata reads for v12**: `_read_metadata_only()` uses 8KB incremental reads to locate the metadata separator, avoiding loading the full file into memory before decryption begins
- **Bounded streaming decrypt**: `decrypt_file()` in streaming.py uses bounded reads instead of a single `fin.read()`, keeping memory usage proportional to chunk size regardless of file size

### Changed

- **`eprint()` replaces `print()` for all non-data output**: ~1,500 call sites across all modules now route to stderr by default, making it safe to capture stdout for scripting and automation

## [1.4.0] - 2026-03-03

### Security

- **Plaintext never touches disk during rekey**: `rekey_file()` no longer writes decrypted plaintext to a temporary file. Plaintext is passed directly as bytes to `encrypt_file()`, eliminating the filesystem race window where plaintext was briefly visible (even with 0o600 permissions) and potentially recoverable on journaling filesystems or SSDs with wear leveling.

### Added

- **In-memory encryption API**: `encrypt_file()` now accepts `bytes`/`bytearray` as `input_file` and `None` as `output_file`, mirroring the pattern `decrypt_file()` already uses. When `output_file=None`, returns encrypted data as bytes instead of writing to disk.
- **Input validation for bytes mode**: Clear `ValidationError` when auto-generated pepper is used with bytes input (requires `--pepper-name`). Integrity plugin gracefully skipped with warning when input is bytes.
- **New test file**: `test_encrypt_bytes.py` with 15 tests covering bytes input, bytes output, full in-memory roundtrip, and input validation.
- **Rekey no-temp-plaintext tests**: 4 new tests in `test_rekey.py` verifying no `.rekey_plain_*` files are created during rekey operations.

### Changed

- **`encrypt_file()` signature**: `input_file` now accepts `Union[str, bytes, bytearray]`, `output_file` accepts `Optional[str]`, returns `Union[bool, bytes]`.
- **`rekey_file()` simplified**: Removed temp plaintext file creation (`mkstemp`/`fchmod`/`write`/`close` block), secure zero-fill cleanup, and `temp_plaintext_path` variable. Memory cleanup of plaintext data now happens after `encrypt_file()` returns.
- **Post-processing plugins**: Skipped when `output_file is None` (no file to post-process).
- **Test coverage**: 1636+ tests passing.

## [1.4.0rc2] - 2026-02-27

### Added

- **Rekey action**: Added `--rekey` CLI action to re-encrypt files with a new password

### Fixed

- **SAST rules**: Relaxed AST security scan for built-in plugins (GHSA-9pgj-v69p-q586 follow-up)

## [1.4.0rc1] - 2026-02-26

### Security

- **CSPRNG for Steganography**: Replaced non-cryptographic random with HMAC-SHA256 CSPRNG (GHSA-vfgx-5q85-58q3)
- **HKDF Salt Parameter**: Added salt parameter to HKDF key derivation (GHSA-j9mh-57cc-665x)
- **Standard PBKDF2 Fallback**: Use standard PBKDF2 for new encryptions in fallback path (GHSA-743f-89fg-x288)
- **Sandbox Bypass Prevention**: Block pathlib/io sandbox bypass for file operations (GHSA-mcjj-qw7m-j3cp)
- **Import Guard Sync**: Synchronized import guard and AST analyzer blocked module lists (GHSA-9pgj-v69p-q586)
- **Path Traversal Sanitization**: Sanitize plugin_id to prevent path traversal (GHSA-8jpj-w975-rwv5)
- **Thread-Safe Module Hiding**: Fixed restore_hidden_modules() logging and thread safety (GHSA-43r4-3hf9-m84q)
- **CORS Default Hardening**: Changed CORS default from wildcard to empty list (GHSA-c65f-x25w-62jv)
- **Trusted Proxy Restriction**: Restricted default trusted proxies to localhost (GHSA-2592-7m3g-7fq6)
- **DB Error Masking**: Stopped leaking DB errors in readiness endpoint (GHSA-2vhw-q7vh-7xv2)
- **Refresh Token Security**: Moved refresh token from query params to POST body (GHSA-4rh7-jwg9-m28m)
- **Key Bundle Verification**: Verify key bundle signature on deserialization (GHSA-8h88-gxp3-j7pg)
- **TOTP Rate Limiter**: Added pluggable backend for TOTP rate limiter (GHSA-h45m-mgcp-q388)
- **SO Path Validation**: Validated .so file paths before loading (GHSA-j48q-4c78-rhf9)
- **Password File Support**: Added --password-file/--password-fd, deprecated --password (GHSA-h3m5-p59h-x88p)
- **Schema Validation**: Raise error when jsonschema unavailable instead of silently passing (GHSA-425g-fjhq-5h92)

### Changed

- Bumped dependencies to fix 8 Dependabot alerts

## [1.4.0b10] - 2026-01-11

### Added

- **Format Version 11: Independent XOR Key Derivation (robust XOR-combiner)**
  - **New Cryptographic Approach**: Implements Independent XOR composition (robust XOR-combiner; Herzberg, HKNRR) where each hash/KDF algorithm processes the same original input (password + salt), and outputs are XOR'd together
  - **Security Guarantee**: Provides "strongest component" security - the derived key is at least as secure as the strongest constituent algorithm, even if all others are compromised
  - **CLI Flag**: New `--independent-xor` flag enables v11 format with Independent XOR composition
  - **Distinction from v10**: Unlike v10 sequential XOR (chains algorithms for anti-parallelization), v11 processes all algorithms independently for maximum cryptographic assurance
  - **Use Cases**: Ideal for scenarios requiring maximum cryptographic confidence and resistance against future algorithm breaks
  - **Initial Normalization**: Adds initial SHA-256 hash of input for defense-in-depth and consistent input normalization
  - **Backward Compatibility**: Files encrypted with v11 format require openssl_encrypt 1.4.0b10+ to decrypt
  - **Cross-Branch Compatibility**: v11 format is compatible with v9 format in the 1.3.x branch

- **Parallel KDF Processing for Performance Optimization**
  - **Multiprocessing Support**: Optional parallel execution of hash algorithms and KDFs using ProcessPoolExecutor
  - **Performance Improvement**: ~2.7x speedup with 8 algorithms on 8-core CPU (sequential: ~8.5s → parallel: ~3.1s)
  - **CLI Flags**:
    - `--parallel-kdf`: Enable parallel processing for key derivation (requires `--independent-xor`)
    - `--kdf-workers N`: Specify number of parallel workers (default: auto-detect based on CPU count)
  - **Progress Reporting**: Queue-based progress aggregation with unified display showing active workers and completion percentage
  - **GUI Integration**: Added parallel KDF progress regex pattern for GUI progress bar support
  - **Key Consistency**: Parallel and sequential modes produce identical keys through deterministic XOR ordering
  - **GIL Bypass**: Uses multiprocessing instead of threading for true CPU parallelism on compute-bound operations

- **New Metadata Schema**: `metadata_v11_schema.json` with `xor_mode` field to distinguish Independent XOR (v11) from Sequential XOR (v10)

- **Comprehensive Test Coverage**:
  - 7 new v11 Independent XOR tests covering basic operations, cross-compatibility, and various encryption algorithms
  - 11 new parallel KDF tests for key consistency, round-trip encryption, worker configuration, and error handling
  - Total: 1573 tests passing (up from 1535)

### Changed

- **Key Derivation Architecture**: v11 format bypasses `generate_key()` function, directly calling `generate_key_independent_xor()` or `generate_key_independent_xor_parallel()` in `encrypt_file()` and `decrypt_file()`
- **Hash Config Handling**: Added automatic flattening of nested hash config structures for v11 metadata creation
- **Format Version Support**: Updated decrypt path to recognize format version 11 in 5 key locations for proper metadata extraction and key derivation

### Performance

- **Sequential v11**: Baseline performance equivalent to v10 (~8.5s for 8 algorithms)
- **Parallel v11**: ~2.7x faster than sequential on 8-core systems (~3.1s for 8 algorithms)
- **Scalability**: Performance scales with CPU core count and number of enabled algorithms
- **Bottleneck**: Slowest algorithm determines parallel mode completion time

## [1.4.0b9] - 2026-01-09

### Fixed

- **Test Infrastructure**: Fixed 6 salt derivation test failures by correcting test suite to use `generate_key()` instead of `multi_hash_password()` for KDF operations
  - **Root Cause**: Tests were calling `multi_hash_password()` with KDF configs (Scrypt, Argon2, PBKDF2, Balloon), but that function only handles regular hash algorithms (SHA-512, BLAKE2b, etc.). KDFs are processed in `generate_key()`
  - **Resolution**: Updated all test calls to use `generate_key()` with proper algorithm parameter
  - **Impact**: All 1535 tests now passing, 0 failures (up from 1532 passed, 6 failed)
  - **Validation**: Format Version 9 security model validated across all KDF algorithms

- **Threefish Cipher Support**: Completed Threefish-512/1024 cipher implementation with HKDF key expansion and proper AEAD integration
  - Added Threefish to `AEAD_ALGORITHMS` list for proper AAD support
  - Fixed nonce size handling in `get_nonce_size()` function
  - Resolved AAD variable handling in Threefish decryption

- **BLAKE3 Buffer Compatibility**: Fixed BLAKE3 buffer sizing for backward compatibility with pre-BLAKE3 encrypted files
  - Enhanced buffer allocation logic to handle files encrypted before BLAKE3 support
  - Zero-initialization for deterministic BLAKE3 keyed hashing

- **Metadata Schema Compatibility**: Made 'mode' field optional in metadata v7 schema for v1.3.4 backward compatibility

- **Type Conversions**:
  - Fixed Scrypt bytearray to bytes conversion in salt derivation
  - Resolved SecureBytes slice handling in XChaCha20 nonce operations

### Changed

- **Test Suite Quality**: Improved test infrastructure and validation
  - 1535 tests passing, 0 failures
  - Format Version 9 validated across PBKDF2, Argon2, Scrypt, Balloon
  - Enhanced cross-version compatibility testing

- **Debug Logging**: Enhanced debug logging for version-aware salt derivation decisions
  - Added logging at KDF function entry points
  - Salt derivation branch logging (SECURE vs PREDICTABLE)

## [1.4.0b8] - 2026-01-08

### 🚨 CRITICAL SECURITY FIX

- **Format Version 9 Implementation**: Implemented secure chained salt derivation for v1.4.x branch
  - **Vulnerability**: Same as v1.3.4 fix (CVSSv3 8.1 HIGH) - predictable salt derivation in multi-round KDF
  - **Resolution**: Unified security model where v7 and v9 use secure chained derivation, v8 uses predictable (backward compatibility only)
  - **Implementation**: Each round uses previous round's output as salt, preventing precomputation attacks
  - **Affected**: All multi-round KDF/hash operations (BLAKE2b, BLAKE3, SHAKE-256, Argon2, Scrypt, Balloon, PBKDF2, HKDF)

### Fixed

- **Pepper Plugin**: Fixed critical scoping errors causing 100+ test failures
  - Resolved variable scoping issues in pepper plugin implementation
  - Fixed HSM plugin loading and dependency management

### Added

- **Flatpak CI/CD**: Added comprehensive Flatpak CI/CD pipeline
  - `flatpak-build`: Regular cached build job
  - `flatpak-build:clean`: Manual clean build without cache
  - `flatpak-publish`: Publish to Flatpak repository
  - `flatpak-publish:clean`: Clean publish from scratch
  - Build and publish stages integrated into GitLab CI

- **Flutter GUI Enhancements**:
  - Remote pepper plugin integration
  - Integrity verification UI
  - Cascade encryption configuration UI
  - Asymmetric encryption configuration
  - YubiKey touch prompt improvements

## [1.3.5] - 2026-01-09

### Fixed

- **BLAKE3 Keyed Hashing Integration**: Fixed BLAKE3 hash algorithm support with proper 32-byte key handling for Format Version 7
  - **Issue**: BLAKE3 was not properly integrated for keyed hashing operations
  - **Resolution**: Implemented BLAKE3-aware buffer sizing with 64-byte minimum allocation
  - **Impact**: BLAKE3 now fully functional. No regression with existing files as BLAKE3 was not used before this bugfix
  - **Compatibility**: Files encrypted with v1.3.5 using BLAKE3 maintain forward compatibility with v1.4.x

- **Metadata Schema Compatibility**: Made 'mode' field optional in metadata v7 schema for v1.3.4 backward compatibility
- **Scrypt Salt Handling**: Fixed bytearray to bytes conversion in Scrypt salt derivation
- **XChaCha20 Nonce Processing**: Resolved SecureBytes slice handling in XChaCha20 nonce operations

### Added

- **Build Tooling**: Comprehensive build scripts for liboqs dependencies
  - `scripts/build_local_deps.sh`: Automated dependency building with version verification
  - `scripts/cleanup_liboqs.sh`: Clean removal of locally built dependencies
  - Environment variable support for custom installation paths

- **CI/CD Infrastructure**: Backported Flatpak build and publish jobs from v1.4.x
  - Automated Flatpak packaging on release branches
  - Clean build jobs for testing without cache

- **Debug Logging**: Enhanced BLAKE3 operation logging for troubleshooting

### Changed

- **Cross-Version Compatibility**: Files encrypted with v1.3.5 are fully compatible with v1.4.x
- **Format Version 7**: Maintains secure chained salt derivation from v1.3.4

## [1.3.4] - 2026-01-07

### Security

- **CRITICAL: Fixed Predictable Salt Derivation in Multi-Round KDF (CVSSv3 8.1 - High)**
  - **CWE-330: Use of Insufficiently Random Values**
  - **Vulnerability**: Multi-round KDF used predictable salt derivation allowing precomputation attacks
  - **Resolution**: Implemented Format Version 7 with secure chained salt derivation
  - **Affected**: BLAKE2b, BLAKE3, SHAKE-256, Argon2, Scrypt, Balloon, PBKDF2, HKDF (multi-round)
  - **Backward Compatibility**: Full backward compatibility maintained (Format Versions 3-6)
  - **Forward Compatibility**: Files encrypted with Format Version 7 require v1.3.4+

### Fixed

- **Test Infrastructure**: Fixed pytest-xdist enum serialization issues
- **Keystore Integration**: Updated keystore to recognize Format Version 7

## [1.3.3] - 2026-01-06

### Changed

- **License Compliance**: Updated license from MIT to Hippocratic License 3.0
  - Fixed Flatpak metainfo.xml project_license field
  - Added explicit license field to setup.py
  - Repository-wide license standardization
  - No functional changes to cryptographic operations

## [1.3.2] - 2025-12-20

### Added

- **Decryption Cost Estimation**: Comprehensive time/memory estimation to prevent DoS attacks
  - Static benchmark data for all hash and KDF algorithms
  - Pre-decryption cost display with 2-second cancellation window
  - `--no-estimate` CLI flag for trusted files

### Fixed

- **CLI Argument Parsing**: Fixed `--no-estimate` flag compatibility with `--progress`
  - Enhanced subcommand detection after global flag preprocessing

## [1.3.1] - 2025-12-18

### Security

- **HSM Security Fix**: Removed `--device=all` from Flatpak manifest
  - Requires explicit USB device opt-in for hardware security modules
  - Enhanced Flatpak permissions with explicit YubiKey/smart card access

### Fixed

- **PQC Key Storage**: Fixed post-quantum private key storage for AEAD algorithms
- **Flatpak Permissions**: Cleaned up invalid filesystem permissions

## [1.4.0] - TBD (Target Stable Release)

### 🚨 CRITICAL SECURITY FIX

#### Format Version 9: Secure Chained Salt Derivation
**SECURITY ADVISORY 2026-01** - Addresses critical vulnerability in multi-round KDF salt derivation

- **Vulnerability (CVSSv3 8.1 - High)**: Format versions ≤8 used predictable salt derivation allowing attackers to precompute all round salts from plaintext metadata, enabling optimized rainbow table attacks
- **Fix**: Implemented secure chained salt derivation where each round uses previous round's output as salt
  - **Security Impact**: Forces sequential computation, prevents precomputation attacks
  - **Backward Compatible**: v8 and below files can still be decrypted
  - **Auto-Upgrade**: New encryptions automatically use v9
- **Affected Components**: All multi-round KDF configurations (Argon2, PBKDF2, Scrypt, Balloon, HKDF) and multi-round hash functions (BLAKE3, BLAKE2b, SHAKE-256)
- **Affected Users**: Files with multi-round KDF (rounds > 1), especially with weak/medium passwords
- **Mitigation**: Upgrade to v1.4.0+ and re-encrypt sensitive files
- **References**: See `docs/security.md` and `docs/metadata-formats.md` for complete security advisory

#### Format Version 7 and 9 Unification
**CRITICAL UPDATE** - Unified v7 (from v1.3.4 branch) and v9 (from v1.4.0 branch) implementations

- **Background**: The security fix was independently implemented in two branches:
  - **Version 7**: Introduced in v1.3.4 (releases/1.3.4 branch) with focus on asymmetric encryption
  - **Version 9**: Introduced in v1.4.0 (feature/v1.4.0-development) with multi-feature release
- **Unification**: Both versions now use identical secure chained salt derivation
  - Pattern: `if format_version >= 7 and format_version != 8:`
  - v7 and v9 produce cryptographically identical keys
  - v8 deliberately excluded for backward compatibility
- **Compatibility**: v1.4.0+ correctly decrypts both v7 and v9 files
- **Security**: Both v7 and v9 provide the same security improvements over v8 and below
- **Implementation**: Updated 9 salt derivation locations, 11 keystore integration points
- **Testing**: Comprehensive v7/v9 compatibility tests verify cryptographic equivalence

### Added

#### Flutter GUI Enhancements
- **Cascade Encryption UI**: Complete cascade encryption configuration interface across all crypto tabs
  - Sub-group headers and algorithm organization
  - Multiple cipher selection with diversity validation
  - Integrated into File Crypto, Text Crypto, and Batch Operations tabs
- **Asymmetric Encryption UI**: Full asymmetric encryption interface
  - Identity management screen with create/import/export
  - Recipient selection for multi-recipient encryption
  - HSM integration (YubiKey Challenge-Response)
  - Integrated into all crypto tabs
- **Remote Plugin Integration**: Network plugin configuration in Settings
  - **Remote Pepper Plugin**: mTLS authentication, TOTP 2FA, deadman switch, panic wipe
  - **Integrity Plugin**: File verification with batch support and audit logging
  - **Keyserver Plugin**: Public key distribution with local caching
- **FIDO2/WebAuthn Support**: HSM credential management with YubiKey touch prompts
  - Real-time touch prompt display (PYTHONUNBUFFERED)
  - Credential management screen
  - Integration across encryption/decryption tabs
- **Algorithm Support Additions**:
  - Threefish-512 and Threefish-1024 post-quantum ciphers
  - Enhanced algorithm picker with grouped display
  - PQC algorithms in Information Tab
  - Support for file format versions 7 and 8

#### CLI & Core Features
- **Integrity Verification Flags**: `--integrity` and `--verify-integrity` for remote metadata hash verification
  - Automatic file_id computation from input file path
  - 409 Conflict handling for re-encryption scenarios
  - Integration with remote integrity module via mTLS
- **Pepper Plugin Integration**: Full CLI integration for remote pepper storage
  - Command-line flags for pepper operations
  - TOTP 2FA support for sensitive operations
  - mTLS certificate-based authentication
- **Steganography Options**: Comprehensive steganography configuration in GUI encryption tab
- **Force Password Option**: Added to encryption and decryption tabs for password override scenarios

### Fixed

#### Critical Bug Fixes
- **Threefish Algorithm Support**: Complete implementation of Threefish-512 and Threefish-1024
  - Added key length support (64 bytes for TF-512, 128 bytes for TF-1024)
  - Implemented HKDF key expansion to derive required key lengths
  - Added proper nonce sizes (32 bytes for TF-512, 64 bytes for TF-1024)
  - Added encryption and decryption logic with AAD support
  - Fixed nonce size mapping in `get_nonce_size()` function
- **Pepper Plugin Scoping Errors**: Fixed critical scoping bugs causing 100+ test failures
  - Resolved variable scope issues in pepper client plugin
  - Fixed authentication and storage operations
- **Integrity Plugin Issues**:
  - Fixed 409 Conflict when re-encrypting files with `--integrity` flag
  - Corrected file_id computation to use input file path instead of output
  - Fixed integrity verification hang in Flutter GUI
- **YubiKey Integration**:
  - Fixed YubiKey notification display in GUI
  - Enabled real-time touch prompt display via PYTHONUNBUFFERED
  - Fixed status message overwrites that hid touch prompts
- **HSM Plugin Loading**: Fixed dependency management and plugin initialization

#### Flatpak Improvements
- **CI/CD Pipeline**: Complete Flatpak build and publish automation
  - Automated flatpak-builder with incremental caching
  - Branch-based flatpak branch naming (from setup.py version)
  - OSTree repository caching to avoid 413 errors
  - Restricted jobs to releases branches and tags only
- **Build System Enhancements**:
  - Proper FLATPAK_BRANCH environment variable respect
  - VERSION extraction from setup.py without setuptools import
  - Python dependencies properly declared in manifest
  - Flutter SDK and build dependencies (which, unzip, patchelf)
  - Docker compatibility flags (--disable-rofiles-fuse)
- **Binary Naming**: Corrected desktop binary from openssl_encrypt_mobile to openssl_encrypt
- **Dependency Fixes**: Added certifi and all missing Python dependencies from requirements-prod.txt

#### GUI Fixes
- **Information Tab**:
  - Fixed hash algorithm display (sha224, sha3-224, sha384 filters)
  - Added PQC algorithms to encryption display
- **Algorithm Picker**:
  - Restored missing hash algorithms
  - Fixed Classical Symmetric consolidation
  - Set PQC and other groups to collapsed by default
- **Settings**:
  - Updated Homepage URL to releases/1.4.0 branch
  - Corrected Documentation and Source Code links
  - Default input type changed to file mode

#### Documentation & Infrastructure
- **Security Documentation**: Added comprehensive SECURITY.md with vulnerability reporting policy
- **Installation Guide**: Complete rewrite of INSTALLATION.md with Flatpak integration
- **README Updates**: Installation section and project URL corrections
- **Markdown Fixes**: Corrected formatting in Flatpak documentation sections
- **Command Syntax**: Fixed to use `-i` flag consistently in all examples

### Changed

#### Infrastructure
- **liboqs Upgrade**: Upgraded to liboqs-python 0.12.0 built from source for HQC algorithm support
- **Project URLs**: Updated to GitHub repository in setup.py
- **Version Management**: Bump to 1.4.0 with PEP 440 / PyPI conformant version strings
- **License**: Explicit Hippocratic-3.0 license declaration in setup.py and Flatpak metadata

#### Development & Testing
- **Test Organization**: Consolidated asymmetric test files into main unittests.py
- **Plugin Security**: Refined AST-based plugin validation to allow legitimate file/network operations
- **Coverage**: Added missing CLI arguments to test coverage
- **Code Formatting**: Applied automated Black formatting fixes

### Deprecated

- **Format Version 8**: Deprecated due to security vulnerability (see SECURITY ADVISORY 2026-01)
  - Read support maintained for backward compatibility
  - Write support disabled (encryption creates v9 files only)
  - Deprecation warning issued when decrypting v8 files

### Security

- **Input Validation**: Added salt, key size, and hash iteration validation in `create_key_from_password`
- **Secure Memory**: Enhanced error handling in secure memory operations
- **Test Coverage**: Added comprehensive tests for salt derivation versions (v8 vs v9)
  - Multi-round KDF behavior tests (PBKDF2, Argon2, Scrypt)
  - Hash function multi-round tests (BLAKE3, BLAKE2b, SHAKE-256)
  - Backward compatibility verification
  - Full encryption/decryption roundtrip tests

## [1.4.0-alpha.1] - 2025-12-31

### Added

#### Infrastructure & Deployment
- **Post-Quantum Keyserver System**: FastAPI-based keyserver for public key distribution with ML-DSA signature verification, bearer token authentication, PostgreSQL backend, and Docker deployment support
  - Public key upload/search/revocation endpoints with authenticated operations
  - CORS configuration and rate limiting for production deployment
  - Plugin architecture supporting HSM integration and custom storage backends
  - Docker support with liboqs 0.12.0 including HQC algorithm support
  - Health check and monitoring endpoints
  - Deployed at: https://keyserver.rm-rf.ch

- **Privacy-Preserving Telemetry System**: Opt-in anonymous telemetry infrastructure with comprehensive privacy controls
  - Plugin-based architecture with configurable data collection
  - Client registration and anonymous usage metrics
  - PostgreSQL backend with FastAPI REST API
  - Docker deployment with automated database migrations
  - Privacy-first design with user consent and data minimization
  - Deployed at: https://telemetry.rm-rf.ch

- **Unified Server Architecture**: Modular FastAPI server with dual authentication system supporting both public and private modules
  - JWT authentication for public modules (keyserver, telemetry)
  - mTLS authentication with self-signed CA for private modules (pepper, integrity)
  - Module isolation with independent enable flags and configuration
  - Docker Compose deployment with PostgreSQL backend
  - Nginx reverse proxy support for production deployments

- **Pepper Module (mTLS-Protected)**: Secure pepper storage system for password hardening with TOTP 2FA
  - 20 REST API endpoints for pepper management
  - Client-side encrypted pepper storage (server stores encrypted blobs)
  - TOTP 2FA with QR code generation (pyotp integration)
  - Deadman switch with configurable check-in intervals and grace periods
  - Panic wipe for emergency pepper deletion (all or single pepper)
  - Auto-registration on first mTLS connection
  - 5 database tables: clients, peppers, deadman, panic_log, totp_backup_codes
  - Access tracking (last_accessed_at, access_count)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes

- **Integrity Module (mTLS-Protected)**: Encrypted file metadata hash verification system
  - 12 REST API endpoints for hash management and verification
  - SHA-256 hash storage for encrypted file metadata
  - Integrity violation detection with comprehensive audit logging
  - Batch verification support (up to 100 files per request)
  - Statistics tracking (success rate, verification counts, last verification)
  - Auto-registration on first mTLS connection
  - 3 database tables: clients, metadata_hashes, verification_log
  - Tamper detection with detailed mismatch warnings
  - Support for multiple algorithm types (symmetric, hybrid, PQC)

- **mTLS Authentication Infrastructure**: Certificate-based authentication for pepper and integrity modules
  - Self-signed CA requirement (public CAs explicitly rejected)
  - Certificate fingerprint authentication (SHA-256)
  - Proxy mode: Nginx terminates mTLS, passes X-Client-Cert-Fingerprint header
  - Direct mTLS mode: Server terminates TLS on dedicated ports (8444, 8445)
  - Trusted proxy IP validation with configurable network ranges
  - Reusable auth handlers: ProxyAuth and MTLSAuth classes
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization

- **Certificate Management Tools**: Automated scripts for self-signed CA and client certificate generation
  - `setup_ca.sh`: Create self-signed CA with passphrase-protected private key
  - `create_client_cert.sh`: Generate client certificates signed by CA
  - Certificate validity: 825 days (~2 years, Apple/Google recommended max)
  - Automated certificate bundle creation for distribution
  - SHA-256 fingerprint calculation and normalization
  - Comprehensive documentation in docs/MTLS_SETUP.md
  - Security best practices and troubleshooting guides
  - Scripts in openssl_encrypt_server/scripts/ directory

#### Client Plugins
- **Pepper Storage Plugin**: Client plugin for secure pepper storage with mTLS authentication
  - Client-side encrypted pepper storage (server never sees plaintext peppers)
  - mTLS authentication with client certificates
  - TOTP 2FA integration for destructive operations
  - Deadman switch with configurable check-in intervals
  - Panic wipe functionality (all or single pepper)
  - Profile management with access tracking
  - Configuration: `~/.openssl_encrypt/plugins/pepper.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig`

- **Integrity Verification Plugin**: Client plugin for encrypted file metadata hash verification
  - Store SHA-256 hashes of encrypted file metadata on remote server
  - Verify file integrity before decryption (tamper detection)
  - Batch verification support (up to 100 files per request)
  - Comprehensive audit logging and statistics tracking
  - mTLS authentication with client certificates
  - Profile management and verification history
  - Utility methods: `compute_metadata_hash()`, `compute_file_id()`
  - Configuration: `~/.openssl_encrypt/plugins/integrity.json`
  - OPT-IN by default (enabled=false)
  - Python API: `from openssl_encrypt.plugins.integrity import IntegrityPlugin, IntegrityConfig`

- **Keyserver Plugin**: Client plugin for post-quantum public key distribution
  - Public key upload, search, and retrieval
  - Local SQLite caching with configurable TTL
  - Bearer token authentication for write operations
  - HTTPS-only connections with timeout configuration
  - Configuration: `~/.openssl_encrypt/plugins/keyserver.json`
  - OPT-IN by default (enabled=false)

- **Telemetry Plugin**: Client plugin for anonymous usage metrics collection
  - Anonymous client identifiers (no personal data)
  - Local SQLite buffering before upload
  - Configurable data collection scopes
  - Background upload with batch processing
  - Full opt-out with data deletion
  - Activation: `--telemetry` flag, `OPENSSL_ENCRYPT_TELEMETRY=1` env, or config
  - OPT-IN by default (disabled)

#### Cryptographic Features
- **Cascade Encryption (Multi-Layer Defense)**: Sequential encryption using multiple cipher algorithms with chained HKDF key derivation
  - Minimum 2 ciphers required, supports unlimited layers
  - Each layer adds entropy to next layer's key derivation
  - Attacker must break ALL ciphers to decrypt data
  - CLI support: `--cascade "aes-256-gcm,chacha20-poly1305,xcha-poly1305"`
  - Automatic cipher diversity validation
  - New metadata format V8 for cascade encryption support

- **Threefish Post-Quantum Ciphers**: Rust-based implementation of Threefish AEAD ciphers
  - Threefish-512 (256-bit post-quantum security level)
  - Threefish-1024 (512-bit post-quantum security level)
  - Memory-hard construction resistant to quantum attacks
  - Native AEAD mode with embedded nonce in ciphertext
  - Maturin-based Rust/Python integration

- **Algorithm Registry System**: Comprehensive cryptographic algorithm registration and validation framework
  - Cipher Registry: 12+ symmetric encryption algorithms with metadata
  - Hash Registry: 15+ cryptographic hash functions
  - KDF Registry: 8 key derivation functions (Argon2, Scrypt, Balloon, HKDF, PBKDF2, RandomX, bcrypt, Fernet)
  - KEM Registry: 9 Key Encapsulation Mechanisms (Kyber, ML-KEM, HQC)
  - Signature Registry: 15 post-quantum signature algorithms (ML-DSA, MAYO, CROSS, Falcon, Dilithium, SPHINCS+)
  - Automatic algorithm validation with security level indicators
  - `crypt list-algorithms` command for browsing available algorithms
  - Integration with configuration wizard and CLI help system

- **HSM-Protected Identity Creation**: Hardware Security Module integration for asymmetric key operations
  - CLI arguments for HSM-protected identity creation: `--hsm`, `--hsm-slot`, `--hsm-pin`
  - HSM_ONLY identities skip password prompts during encryption/decryption
  - Seamless auto-detection when `--with-key` provided
  - Save/load HSM identities without password requirements

#### Testing & Quality Assurance
- **Modularized Test Suite**: Domain-specific test file organization for better parallelization
  - Split CLI tests into 3+ parallel-friendly subclasses
  - Optimized KDF parameters for faster test execution
  - High-CPU GitLab runner tags for improved CI performance
  - Worksteal distribution for dynamic load balancing
  - Comprehensive cascade encryption test coverage

- **Performance Optimizations**: Test suite execution time improvements
  - Reduced KDF rounds in CLI tests (faster execution)
  - Reduced Balloon time_cost in derivation tests
  - Test-only Kyber file optimization
  - Test duration diagnostics for performance monitoring

#### Documentation & Security
- **SECURITY.md Policy**: Comprehensive vulnerability reporting documentation
  - GitHub Security Advisory as preferred reporting method
  - PGP-encrypted email alternative (PGP Key: C8E4 C58E 83AB B314 74C0 E108 0271 3C63 792B 8986)
  - 48-hour initial response commitment
  - Coordinated disclosure practices
  - CVE assignment for critical vulnerabilities
  - Security Hall of Fame for responsible disclosure
  - Added to ALL branches (including EOL releases)

- **Documentation Reorganization**: Cleaned up root directory and organized documentation
  - Moved analysis/audit files to `openssl_encrypt/docs/`
  - Moved test runner scripts to `tests/` directory
  - Removed implementation plan files from repository
  - Consolidated security documentation structure

- **Pre-Commit Hook**: Branch-specific plan file enforcement
  - Auto-remove plan files on main branch
  - Configurable per-branch rules
  - Prevents accidental plan file commits

### Changed

#### Core Features
- **Cascade Encryption Integration**: Full CLI and core module integration
  - Added `--cascade` parameter to encryption commands
  - Support for custom cipher chains with validation
  - JSON schema validation for V7 and V8 metadata formats
  - Cascade variables initialized for all format versions

- **Algorithm Registry Integration**: Replaced hardcoded algorithm lists with registry system
  - CLI helper utilities for registry-based operations
  - Registry-based algorithm validation
  - Improved help text with security level recommendations
  - Configuration wizard integration

- **Identity Management**: Enhanced asymmetric key handling
  - Updated asymmetric encryption format
  - Missing KDF arguments added to subparser for feature parity
  - Skip interactive KDF security prompts in non-TTY environments
  - Improved HSM option handling in identity CLI

#### Build & Dependencies
- **Rust Extension Build**: Integrated Threefish Rust extension into build process
  - Maturin build system for Python/Rust integration
  - Added patchelf for wheel building compatibility
  - CI build step for Threefish extension
  - Flatpak build with proper Threefish wheel handling

- **Docker Infrastructure**: Enhanced Docker builds for server components
  - liboqs 0.12.0 built from source for HQC support
  - Added pkg-config and python3-dev build dependencies
  - Multi-stage Docker builds for optimized images
  - PostgreSQL database integration for both servers

#### Code Quality
- **Security Enhancement**: SecureBytes implementation across all registries
  - KDF registry uses SecureBytes for sensitive data
  - Cipher registry uses SecureBytes for keys (comprehensive implementation)
  - Signature registry uses SecureBytes for secret keys
  - KEM registry uses SecureBytes for sensitive data
  - Comprehensive security audit updates

- **CI/CD Improvements**: Multiple CI pipeline enhancements
  - Docker-based CI support for server components
  - Parallel test execution with loadscope distribution
  - High-CPU runner allocation for faster execution
  - Test duration tracking and diagnostics

### Fixed

#### Critical Issues
- **Stdin Reading Bug**: Resolved decryption failures when reading from stdin
- **CLI Test Failures**: Fixed 2+ CLI test failures related to HSM mocking and argument handling
- **Asymmetric Encryption Tests**: Updated tests for new format compatibility
- **Identity CLI**: Fixed HSM mock issues in identity CLI tests
- **NoneType Comparison**: Removed debug statements causing NoneType comparison errors (fixed 15 tests)

#### Security Fixes
- **RandomX SIGILL Crash**: Prevented RandomX SIGILL crash during test collection in CI
- **Cipher Registry**: Complete SecureBytes implementation across all cipher operations
- **Algorithm Validation**: Fixed auto-detection logic when `--with-key` provided

#### Build System
- **Threefish AEAD Mode**: Fixed Threefish ciphers to embed nonce in ciphertext (like AES-GCM)
- **Flatpak Build**: Cleaned old wheels before Threefish build to prevent conflicts
- **Test Collection**: Use relative paths for test files to prevent CI collection failures

#### Compatibility
- **Metadata V7 Format**: Added quiet and verbose parameters to create_metadata_v7
- **RandomX KDF**: Updated to use correct package structure
- **KDF Arguments**: Fixed missing arguments for proper format compatibility

#### Server Infrastructure
- **SQLAlchemy Reserved Name**: Fixed integrity module INClient model using reserved 'metadata' column name
  - Renamed to 'client_metadata' to avoid SQLAlchemy DeclarativeAPI conflicts
  - Prevents "Attribute name 'metadata' is reserved" error during table creation
- **Environment Protection**: Added .gitignore to openssl_encrypt_server/ to protect sensitive files
  - Excludes .env files from version control
  - Excludes private keys (*.key, *.pem, *.p12, *.pfx)
  - Prevents accidental exposure of credentials and certificates
- **Server Info Endpoint**: Updated /info endpoint to include pepper and integrity module status
  - Shows enabled/disabled status for all four modules (keyserver, telemetry, pepper, integrity)
  - Displays endpoint paths for each module

### Security

#### Security Enhancements
- **Comprehensive SecureBytes Implementation**: All cryptographic registries now use secure memory handling
  - KDF, Cipher, Signature, and KEM registries fully secured
  - Automatic zeroing of sensitive data after use
  - Thread-safe secure memory operations
  - Complete security audit resolution

- **Algorithm Registry Security**: Enhanced cryptographic algorithm security
  - Validation framework prevents unsafe algorithm combinations
  - Security level indicators for all algorithms
  - Deprecated algorithm warnings integrated
  - Comprehensive algorithm metadata tracking

- **Keyserver Security**: Production-grade security for key distribution
  - ML-DSA signature verification for all uploaded keys
  - Bearer token authentication for write operations
  - Rate limiting and CORS protection
  - PostgreSQL backend with parameterized queries

- **Telemetry Privacy**: Privacy-first telemetry implementation
  - Opt-in by design with explicit user consent
  - Anonymous client identifiers
  - Minimal data collection with configurable scopes
  - Transparent data usage policies

- **Pepper Module Security**: Hardened pepper storage with multiple layers of protection
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - TOTP 2FA for destructive operations (panic wipe, account deletion)
  - Client-side encryption (server never sees plaintext peppers)
  - Fernet encryption for TOTP secrets at rest
  - Argon2 hashing for backup codes
  - Deadman switch with grace periods to prevent accidents
  - Comprehensive audit logging (panic events, access tracking)
  - Opt-in by design (disabled by default)

- **Integrity Module Security**: Tamper detection for encrypted file metadata
  - mTLS certificate authentication (self-signed CA only, public CAs rejected)
  - SHA-256 hash verification with integrity violation detection
  - Comprehensive audit logging (all verification attempts tracked)
  - Batch verification with result aggregation
  - Statistics tracking for security monitoring
  - Support for detecting metadata tampering before decryption
  - Opt-in by design (disabled by default)

- **mTLS Authentication Security**: Certificate-based authentication for private modules
  - Self-signed CA requirement prevents unauthorized certificate issuance
  - Public CAs explicitly rejected (Let's Encrypt, DigiCert, etc.)
  - Certificate fingerprint (SHA-256) as unique client identifier
  - Trusted proxy IP validation prevents header injection attacks
  - Certificate DN extraction for client identification
  - Automatic certificate fingerprint normalization
  - No pre-registration required (auto-register on first connection)

#### Security Metrics
- **All Critical Registry Issues Resolved**: Complete SecureBytes implementation across all registries
- **Comprehensive Security Documentation**: SECURITY.md added to all 20 branches
- **Zero Known HIGH/MEDIUM Vulnerabilities**: Security audit completion
- **Enhanced Secure Memory Handling**: Registry-wide secure memory practices

### Removed
- **Plan Files**: Removed implementation plan files from repository
  - asymetric.md, hsm_asymmetric.md, mobile.md
  - keyserver_plan.md, telemetry_plan.md
  - TELEMETRY_IMPLEMENTATION_SUMMARY.md
- **Root Convenience Wrapper**: Removed build-flatpak.sh from root directory
- **Test Artifacts**: Cleaned up test files for plan file hook validation

### Dependencies
- **liboqs**: Updated to 0.12.0 (built from source) for HQC algorithm support
- **FastAPI**: Added for keyserver and telemetry server REST APIs
- **PostgreSQL**: Added psycopg2-binary for server database backends
- **Maturin**: Added for Rust/Python integration (Threefish cipher)
- **All existing dependencies**: Maintained at current secure versions

### Infrastructure
- **Production Servers Deployed**:
  - Keyserver: https://keyserver.rm-rf.ch (FastAPI + PostgreSQL)
  - Telemetry: https://telemetry.rm-rf.ch (FastAPI + PostgreSQL)
- **Docker Support**: Complete Docker infrastructure for both servers
- **Plugin Architecture**: Extensible plugin system for both keyserver and telemetry

### Testing
- **127+ commits** of new functionality and improvements
- Comprehensive cascade encryption test suite
- Threefish cipher integration tests
- Algorithm registry validation tests
- HSM-protected identity tests
- Server endpoint integration tests
- Optimized test execution performance

### Breaking Changes
**None** - Version 1.4.0-alpha.1 maintains backward compatibility with all existing encrypted files and configurations. New features (cascade encryption, Threefish ciphers) use new metadata formats (V8) but existing files remain fully compatible.

### Migration Guide
This is an **alpha release** for testing purposes. While backward compatible, new features should be tested thoroughly before production use:
- **Cascade Encryption**: Test with `--cascade "cipher1,cipher2"` flag
- **Threefish Ciphers**: Available as `threefish-512` and `threefish-1024`
- **Keyserver**: Deploy using Docker or test at https://keyserver.rm-rf.ch
- **Telemetry**: Opt-in system, review privacy policy before enabling

**Alpha Testing Notes**:
- This is a pre-release version intended for testing and feedback
- Production deployment recommended only for non-critical workloads
- Report issues via GitHub Security Advisory or encrypted email
- Final 1.4.0 release planned for Q1 2026

### Contributors
- **Tobi** - Lead developer, cascade encryption, keyserver, telemetry, algorithm registry
- **Claude (Sonnet 4.5)** - Architecture design, security review, testing framework, documentation

---

## [1.3.0] - 2025-12-15

### Added

#### Cryptographic Features
- **RandomX Proof-of-Work KDF**: CPU-optimized key derivation function with light mode (256MB memory) and fast mode (2GB memory) for enhanced security against GPU/ASIC attacks
- **Implicit RandomX Activation**: Automatically enable RandomX when parameters are specified with intelligent default round configuration
- **Steganography Support in Flutter GUI**: Complete integration of data hiding capabilities in desktop GUI
- **Flexible Argument Parsing**: Global flags now support flexible argument parsing for improved CLI usability

#### Testing & Quality Assurance
- **Comprehensive Test Suite**: New `crypt test` command with fuzzing, side-channel analysis, Known-Answer Tests (KAT), performance benchmarking, and memory safety testing
- **Security Audit Logging**: Comprehensive logging system for security events with security_logger and security_report modules
- **Configuration Analysis Tool**: Smart recommendations system with security scoring and configuration validation

#### Infrastructure & Deployment
- **D-Bus Client Examples**: Python, Rust, and Shell client examples demonstrating cross-language compatibility
- **Docker Build Infrastructure**: Local Docker/Podman build scripts with optimized 140MB runtime images
- **QR Code Key Distribution**: Air-gapped keystore operations via portable media
- **Portable USB Encryption**: Unified portable media encryption script with automated integrity verification
- **CI/CD Updates**: Docker-based CI pipeline support with GitLab CI integration

#### Documentation
- **Security Review Documentation**: Comprehensive SECURITY_REVIEW_v1.3.0.md with detailed security audit
- **Docker Build Documentation**: Complete Docker setup guide in docker/README.md
- **D-Bus Integration Guide**: Comprehensive D-Bus service documentation
- **Mobile Implementation Guides**: PQC mobile requirements and chained hash implementation docs

### Changed

#### Core Features
- **RandomX KDF Integration**: Full integration with intelligent implicit enable when parameters detected
- **Default Configuration Behavior**: Enhanced security requiring hash configuration for new encryptions
- **Error Handling**: Improved error messages with comprehensive debug logging replacing print statements

#### Plugin System
- **Thread Safety**: Refactored threading resource management preventing global state pollution
- **Timeout Implementation**: Replaced simple timeout with reliable multiprocessing-based mechanism
- **Queue Handling**: Fixed multiprocessing queue deadlock through improved process management

#### Build & Dependencies
- **Flatpak Dependencies**: Updated manifest dependencies matching requirements-prod.txt
- **Pillow Version**: Relaxed to allow 11.x releases (updated to 11.3.0)
- **NumPy Compatibility**: Upgraded to 2.x for Alpine Linux compatibility

#### Code Quality
- **Path Canonicalization**: Fixed handling for special device files (/dev/stdin, /dev/null, /dev/stdout)
- **Python 3.13 Compatibility**: Replaced datetime.UTC with timezone.utc
- **String Formatting**: Fixed f-strings without placeholders and removed unnecessary imports
- **CI Configuration**: Added amd64 runner tags preventing ARM64 execution

### Fixed

#### Critical Issues
- **Default Configuration Decryption**: Resolved metadata generation inconsistency causing decryption failures
- **PQC Dual Encryption Tests**: Fixed test failures through improved binary prefix handling
- **Multiprocessing Segfaults**: Implemented proper 'spawn' method instead of default fork method
- **Plugin Sandbox Deadlock**: Resolved multiprocessing queue deadlock preventing proper termination

#### Test Infrastructure
- **Import Path Corrections**: Fixed duplicate module imports in pytest
- **Mock Patch Paths**: Corrected mock.patch module paths in test_generate_password_cli
- **Flaky Tests**: Fixed two intermittent test failures
- **API Compatibility**: Updated Advanced Testing Framework encrypt_file API calls

#### Build System
- **Docker Image Sizing**: Optimized build reducing image to 140MB with proper runtime dependencies
- **Build Tool Dependencies**: Added necessary build tools for Python package compilation
- **YAML Parsing**: Fixed YAML syntax errors and f-string issues in CI configuration

#### Compatibility
- **Keystore Schema**: Made schema more flexible for version compatibility
- **Backward Compatibility**: Fixed v1.3.0 decryption compatibility without prior hashing
- **PQC Validation**: Added missing PQC algorithms to metadata v5 schema
- **Legacy Algorithms**: Added legacy algorithm names for keystore compatibility

### Security

#### Vulnerability Resolutions
- **MED-2: D-Bus Symlink Attack Prevention (RESOLVED)**
  - Implemented O_NOFOLLOW protection in safe_open_file() utility for atomic TOCTOU protection
  - Added secure_mode parameter to encryption/decryption functions for D-Bus service security
  - Created comprehensive symlink attack tests with 100% pass rate
  - Eliminates symlink-based directory traversal attacks in D-Bus service
  - Maintains CLI behavior compatibility (secure_mode=False allows symlinks)

- **LOW-5: Debug Mode Security Warning (RESOLVED)**
  - Added prominent security warning box when --debug flag is enabled
  - Clear "DO NOT use with production data" messaging
  - Updated --debug help text across crypt_cli.py, crypt_cli_subparser.py, and crypt.py
  - Warning displayed before any sensitive logging occurs

#### Security Enhancements
- **Comprehensive Security Review**: SECURITY_REVIEW_v1.3.0.md with 0 CRITICAL, 0 HIGH, 3 MEDIUM, 4 LOW findings
- **Security Audit Logging**: Comprehensive audit logging for security events throughout codebase
- **D-Bus Path Validation**: Enhanced directory whitelisting for D-Bus file operations
- **Plugin Validation**: Added strict mode with configurable bypass options
- **Subprocess Safety**: Removed shell=True from subprocess calls with proper list-based arguments

#### Security Metrics
- **Overall Security Score**: 8.8/10 (improved from 8.5/10)
- **Input Validation**: 9.5/10 (improved with O_NOFOLLOW protection)
- **Cryptography**: 9.5/10
- **Authentication**: 9.0/10
- **Memory Safety**: 9.0/10
- **Dependency Security**: 10/10 (zero vulnerable dependencies via pip-audit)
- **Status**: APPROVED FOR PRODUCTION

### Removed
- **Video Steganography**: Removed implementation due to fundamental reliability issues
- **Video Dependencies**: Removed video steganography dependencies from requirements
- **Test Artifacts**: Cleaned up steganography test images and debug files

### Dependencies
- **Pillow**: Updated to 11.3.0 (relaxed constraint to allow 11.x releases)
- **NumPy**: Upgraded to 2.x for Alpine Linux compatibility
- **Cryptography**: Maintained at 44.0.3+
- **Argon2-cffi**: Maintained at 23.1.0+
- **pip-audit**: All dependencies verified with zero vulnerable packages

### Documentation
- Added SECURITY_REVIEW_v1.3.0.md with comprehensive security audit
- Added docker/README.md for Docker build and deployment
- Added examples/dbus_clients/ with Python, Rust, and Shell examples
- Enhanced plugin development guides with security architecture details

### Testing
- 128+ encryption-related unit tests passing
- Comprehensive plugin system tests with proper isolation
- Full D-Bus service tests with symlink attack scenarios
- Docker build tests with optimized 140MB image
- RandomX integration tests with fallback handling
- Post-quantum cryptography dual encryption tests

### Breaking Changes
**None** - Version 1.3.0 maintains full backward compatibility with all existing encrypted files and configurations.

### Migration Guide
No migration required. v1.3.0 is a drop-in replacement for v1.2.x installations.

**Note**: Debug mode (--debug) now displays a prominent security warning. This is intentional to remind users that debug output contains sensitive information.

### Contributors
- **Tobi** - Lead developer, security enhancements, comprehensive testing
- **Claude (Sonnet 4.5)** - Security review, documentation, testing framework

## [1.2.0] - 2025-08-16

### Added
- **Flutter Desktop GUI**: Professional desktop GUI application built with Flutter providing native Wayland and X11 support
- **Advanced CLI Integration**: Complete Flutter-to-CLI bridge service with real-time progress monitoring and error handling
- **Comprehensive Settings System**: Professional settings interface with theme switching, cryptographic defaults, and debug features
- **Desktop UX Excellence**: Professional menu bar, keyboard shortcuts (Ctrl+O, Ctrl+S, F1), drag & drop file operations
- **Algorithm Configuration UI**: Advanced parameter tuning interface for all KDFs (Argon2, Scrypt, Balloon, HKDF)
- **Post-Quantum Algorithm UI**: Complete interface for ML-KEM, Kyber, HQC, MAYO, and CROSS algorithms
- **Flatpak Desktop Integration**: Complete Flatpak packaging with desktop file, icons, and system integration

### Changed
- **GUI Architecture**: Migrated from tkinter to Flutter for superior desktop experience and cross-platform compatibility
- **Flatpak Launcher**: Simplified launcher focusing on Flutter GUI with tkinter support removed from release branches
- **User Interface**: Desktop-optimized layout with NavigationRail, tabbed interface, and professional visual design
- **File Operations**: Native desktop file dialogs with drag & drop support replacing basic file selection
- **Algorithm Selection**: Interactive algorithm picker with security level recommendations and performance guidance

### Removed
- **PBKDF2 Support**: Removed legacy PBKDF2 key derivation function from encryption operations due to security concerns
- **Whirlpool Hash**: Removed deprecated Whirlpool hash algorithm from encryption operations for security hardening

### Fixed
- **Wayland Compatibility**: Native Wayland support through Flutter eliminating X11 authorization issues
- **Display Server Support**: Robust support for both Wayland and X11 environments without manual configuration
- **Desktop Integration**: Proper desktop environment integration with system theming and accessibility support
- **Performance**: Significant UI responsiveness improvements through native Flutter rendering

### Security
- **Reduced Attack Surface**: Elimination of complex X11/XWayland compatibility layers in Flatpak environment
- **Native Desktop Security**: Flutter's native platform integration provides better sandboxing than X11-based solutions
- **Streamlined Permissions**: Simplified Flatpak permissions removing unnecessary X11 fallback mechanisms
- **Algorithm Hardening**: Removed deprecated PBKDF2 and Whirlpool algorithms to eliminate weak cryptographic options

## [1.1.0] - 2025-06-26

### Added
- Segregated CLI help system with two-tier structure (global + command-specific)
- Context-aware help display showing only relevant options per command
- Improved command discovery with comprehensive overview in global help
- Command-specific argument parsing for better user experience

### Changed
- Enhanced CLI help output for better usability and reduced cognitive load
- Global help now provides clear command overview and navigation guidance
- Encrypt command help shows only encryption-relevant options and algorithms
- Decrypt command help shows only decryption-relevant options (no algorithm selection)
- Generate-password, shred, and utility commands show focused option sets

### Technical
- Added crypt_cli_subparser.py module for command-specific argument handling
- Implemented version-aware algorithm filtering (excludes 1.1.0-only MAYO/CROSS algorithms)
- Maintained full backward compatibility with all existing CLI usage patterns
- No changes to core cryptographic functionality or file formats

## [1.0.0] - 2025-06-21

### Added
- Official production release milestone
- Enterprise-grade quantum-resistant cryptographic capabilities
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC algorithms)
- Production-grade type safety and runtime stability
- Enterprise-ready keystore management for PQC keys
- Industry-leading code quality standards with comprehensive static analysis

### Changed
- Status updated to Production Release / Stable
- Full backward compatibility maintained with all previous file formats
- Production deployment readiness achieved

### Security
- Comprehensive security hardening with constant-time operations
- Final security audit completion with zero HIGH/MEDIUM severity issues
- Production-ready security posture established

## [1.0.0-rc3] - 2025-06-16

### Documentation
- Major documentation consolidation from 37+ files to 10 comprehensive guides (73% reduction)
- Updated README.md Documentation Structure section with clickable links
- Added June 2025 documentation restructuring to RELEASE_NOTES.md
- Consolidated user documentation into user-guide.md and keystore-guide.md
- Consolidated security documentation into security.md, algorithm-reference.md, and dependency-management.md
- Consolidated technical documentation into metadata-formats.md and development-setup.md
- Integrated ML-KEM CLI support documentation into algorithm-reference.md
- Integrated HQC algorithm completion status from NEXT.md into TODO.md

### Security

- Updated `cryptography` dependency from `>=42.0.0,<43.0.0` to `>=44.0.1,<45.0.0` to address CVE-2024-12797
- Added specific version constraints to all dependencies to prevent unexpected breaking changes
- Implemented proper version pinning with both lower and upper bounds for all dependencies
- Added `bcrypt~=4.3.0` with compatible release specifier
- Added pre-commit hooks for security scanning
- Integrated Bandit for Python security code analysis
- Added pip-audit for dependency vulnerability scanning (replacing Safety)
- Created custom gitlab_dependency_scan.py script for reliable CI security scanning
- Added security scanning to CI pipeline
- Implemented Software Bill of Materials (SBOM) generation
- Added GitLab security dashboard integration

### Build System

- Added pyproject.toml for properly specifying build dependencies
- Implemented lock files using pip-tools for reproducible builds
- Created requirements-prod.txt and requirements-dev.txt lock files
- Added dependency update script (scripts/update_dependencies.sh)
- Updated setup.py to use lock files for dependencies
- Added setup_hooks.sh script for easy pre-commit installation

## [1.0.0-rc2] - 2025-06-16

### Fixed
- Resolved all critical MyPy type errors that could cause runtime failures in post-quantum cryptography operations
- Fixed variable naming conflicts between AESGCM and PQCipher classes
- Corrected string/bytes type mismatches in password handling
- Removed invalid function parameters causing TypeErrors
- 90%+ critical runtime issues resolved (type errors reduced from 529 to ~480)

### Added
- HQC algorithm support fully implemented (hqc-128/192/256-hybrid) with comprehensive testing
- **HQC Production Readiness**: Complete HQC algorithm implementation with 15 test files covering all symmetric encryption combinations
- **HQC Security Validation**: Comprehensive error handling tests for invalid keys, corrupted data, wrong passwords, and algorithm mismatches
- **HQC Integration**: Full keystore integration, dual-encryption support, and file format v5 compatibility
- Complete post-quantum cryptography support (Kyber, ML-KEM, HQC)
- Industry-leading code quality standards
- Production-grade stability and reliability

### Security
- Security analysis confirmed 0 HIGH/MEDIUM severity issues
- All core encryption functionality verified working
- HQC algorithms pass all security validation tests and attack vector analysis

## [1.0.0-rc1] - 2025-05-16

### Added
- Comprehensive multi-layered static code analysis with 7 GitLab CI jobs
- 18+ pre-commit hooks for immediate development feedback
- Legacy algorithm warning system for deprecated cryptographic algorithms
- Comprehensive code formatting via Black and isort
- Enhanced CI pipeline with Docker improvements and job isolation

### Changed
- Repository cleanup removing unnecessary development artifacts

### Security
- Industry-leading code quality standards implementation
- Comprehensive static analysis integration
- Enhanced security scanning capabilities

## [0.9.2] - 2025-05-15

### Added
- CRYPT_PASSWORD environment variable support for CLI with secure multi-pass clearing
- Comprehensive GUI password security with SecurePasswordVar class
- Extensive unit test suite with 11 tests covering environment variable password handling

### Security
- Enhanced password handling security across all interfaces
- Secure clearing verification for environment variables

## [0.9.1] - 2025-05-14

### Added
- ML-KEM algorithms (ML-KEM-512/768/1024)
- HQC algorithms re-enabled with comprehensive testing (HQC-128/192/256)
- Enhanced keystore integration for all PQC algorithms
- Improved concurrent test execution safety

### Removed
- bcrypt dependency due to incompatible salt handling

### Security
- Extended quantum-resistant algorithm support
- Comprehensive post-quantum testing infrastructure
- Enhanced keystore security features

## [0.9.0] - 2025-04-16

### Added
- Constant-time cryptographic operations implementation
- Secure memory allocator for cryptographic data
- Standardized error handling to prevent information leakage
- Python 3.13 compatibility
- Enhanced CI pipeline with pip-audit scanning
- SBOM generation (Software Bill of Materials)
- Thread safety improvements with thread-local timing jitter

### Security
- Comprehensive dependency security with version pinning
- Major security hardening release
- Backward compatibility maintained across all enhancements

## [0.8.2] - 2025-04-15

### Fixed
- Python version compatibility fixes for versions < 3.12
- More resilient Whirlpool implementation during package build
- Enhanced build system reliability
- Cross-platform compatibility improvements

## [0.8.1] - 2025-04-14

### Added
- New metadata structure v5 with backward compatibility
- User-defined data encryption when using PQC
- Enhanced PQC flexibility with configurable symmetric algorithms
- Comprehensive testing and documentation updates

## [0.7.2] - 2025-03-16

### Added
- New metadata structure with backward compatibility
- Improved data organization and structure
- Enhanced file format versioning
- All tests passing with updated documentation

## [0.7.1] - 2025-03-15

### Added
- Complete keystore implementation for post-quantum keys
- Comprehensive testing - all tests passing
- Updated documentation for keystore functionality

### Breaking Changes
- Breaking release for keystore feature of PQC keys

## [0.7.0-rc1] - 2025-03-14

### Added
- PQC key management system
- Local encrypted keystore for post-quantum keys
- Last major feature for release candidate phase

### Breaking Changes
- Breaking release introducing keystore feature

## [0.6.0-rc1] - 2025-02-16

### Added
- Feature-complete post-quantum cryptography implementation
- Hybrid post-quantum encryption architecture
- Complete post-quantum algorithm support

### Breaking Changes
- Breaking release for post-quantum cryptography

## [0.5.3] - 2025-02-15

### Added
- Additional buffer overflow protection
- Enhanced secure memory handling
- Improved memory safety

### Security
- Security-focused bug fixes
- Enhanced memory protection

## [0.5.2] - 2025-02-14

### Added
- Post-quantum resistant encryption via hybrid approach
- Kyber KEM integration for quantum resistance
- Hybrid encryption architecture combining classical and post-quantum
- Future-proof cryptographic foundation

## [0.5.1] - 2025-02-13

### Fixed
- More reliable commit SHA integration into version.py
- Enhanced build process reliability
- Improved version tracking

## [0.5.0] - 2025-01-16

### Added
- BLAKE2b and SHAKE-256 hash algorithms
- XChaCha20-Poly1305 encryption support
- Expanded cryptographic algorithm portfolio
- Enhanced security options

## [0.4.4] - 2025-01-15

### Added
- Scrypt support
- Additional hash algorithms implementation
- Enhanced key derivation options
- Improved password security

## [0.4.0] - 2025-01-14

### Added
- Secure memory handling implementation
- Improved password strength validation
- Memory security enhancements
- Enhanced data protection

## [0.3.0] - 2025-01-13

### Added
- Argon2 key derivation support
- Memory-hard key derivation function
- Enhanced password-based security
- Industry-standard KDF implementation

## [0.2.0] - 2025-01-12

### Added
- AES-GCM support
- ChaCha20-Poly1305 encryption
- Multiple encryption algorithm support
- Cryptographic algorithm flexibility

## [0.1.0] - 2025-01-11

### Added
- Initial public release
- Basic file encryption/decryption
- Fernet encryption (AES-128-CBC)
- Secure password-based encryption
- Foundation cryptographic features
