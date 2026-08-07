# Open questions from the autonomous run of 2026-08-07

Things I did not decide on my own, recorded here rather than guessed at.
Each names the issue it belongs to, so it can be answered there and this
file shrinks.

## gitlab#148 — envelope rewrite: three residuals left deliberately

All three were raised in review, all three are real, none blocks the fix
that landed. They need a product decision rather than a code judgement.

(A fourth — a same-file rewrite of a FIFO or device node, which cannot be
backed up and so could not be made recoverable — is no longer open: the
writer now refuses that case outright instead of truncating.)

**Permission semantics now depend on which path runs.** The atomic path
preserves the original file's mode; the write-through path forces 0600 via
`set_secure_permissions`. So a 0644 envelope — restored from a backup, or
produced by another tool — used to be *tightened* on rewrite and now keeps
0644. `os.replace` also installs a new inode, so POSIX ACLs, xattrs, the
SELinux label and ownership are not carried across. Question: should a
same-file rewrite tighten a too-open mode (and warn), or is preserving what
the user set the correct behaviour?

**The write-through path is O(file) and needs free space equal to the file.**
Making the excluded cases recoverable means copying the original before
overwriting it, so `add-recovery`, `remove-recovery` and the envelope rekey
fast-path — all documented as O(header), "without re-encrypting the bulk" —
read and write the whole file when the target is a symlink or has a second
hard link. A 200 GB envelope with a second link now needs 200 GB free to have
a recovery slot removed, and a `mkstemp` that hits ENOSPC or a read-only
directory aborts an operation that previously succeeded. It fails closed, so
this is availability rather than safety. Question: leave it, or warn (or
refuse without an opt-in) above some size threshold?

**A revoked wrapping is no longer overwritten, and on one path a whole extra
copy of it is created.** Two distinct residues, same question:

- On the *atomic* path `os.replace` unlinks the old inode, so the blocks
  holding the removed slot's wrapped DEK stay in free space until
  reallocated and are recoverable with raw device access. That is free-space
  residue the old truncating write did not leave.
- On the *write-through* path the truncating write does overwrite the
  original blocks — but the `.slotbak_` backup is a byte-for-byte copy of
  the pre-change envelope that the previous implementation never created at
  all. It is removed on success and mode 0600 throughout, so this is about
  the window and the crash case, not a standing leak.

Either way the wrapped DEK is only usable by someone holding the revoked
credential, so this is not a key compromise — but "revoked" now means
"unreferenced", not "destroyed". Question: document that limit, or shred
best-effort via `crypt_utils.secure_shred_file` (with the usual caveat that
CoW and journalling filesystems defeat it)? Shredding the backup would
double an already-O(file) path, which is why it was not done by default.

## gitlab#192 — 1.5.x GUI, two items left

Steganography is removed. Still emitted by that line's GUI, and registered
in the argv lint rather than fixed:

- `--pbkdf2-iterations` — the PBKDF2 chain stage was removed in 1.5, so the
  flag is gone. Dropping it from the GUI is mechanical; I left it because it
  sits in the shared encrypt path and I could not compile-check Dart.
- `identity import --data/--alias` — gitlab#164's import rework is 1.4.x
  only, so GUI contact import is broken on 1.5.x exactly as it was on 1.4.x
  before that fix. Question: port #164 to 1.5.x, or accept it?

## Verification that could not be done here

There is no Flutter toolchain in this container, so **no Dart was compiled
or tested** in this run. `flutter analyze` was clean when run externally
against an earlier state, but four later commits touched Dart — including a
~300-line steganography removal across an interleaved widget file. Run
`cd desktop_gui && flutter analyze && flutter test` before relying on any
of it.

The signed source-integrity manifest is also stale: `crypt_cli.py`,
`crypt_cli_subparser.py` and `crypt_core.py` all changed, so
`verify-integrity` reports a false tamper until the manifest is regenerated
and re-signed with the release key.
