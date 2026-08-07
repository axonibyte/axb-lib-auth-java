# Changelog

## 0.2.0

Security and correctness work across both classes. **Read the breaking changes before
upgrading**: several contracts changed deliberately, and one stored-record compatibility
bug in `0.1.0` is fixed here.

### Breaking

- **`SessionEngine(String, int)` is removed.** Use `SessionEngine(String, Duration)`.
  The `int` was documented as minutes and implemented in seconds, so a caller following
  the javadoc got a window sixty times shorter than it asked for. Changing the unit under
  an unchanged signature would have silently handed such a caller a sixty-times-*longer*
  session, so the constructor is gone and the mistake is a compile error.
- **`SessionEngine` tokens issued by earlier versions no longer verify.** The old format
  is not readable and deliberately has no legacy path — see below.
- **`SessionEngine` refuses a null or empty secret**, and a non-positive validity, at
  construction. Previously a null secret yielded an all-zero AES key, silently.
- **`Credentialed.sign` throws `CryptoException`** when there is no private key, rather
  than returning `""`. The method already declared the exception, so this is
  source-compatible.
- **`Credentialed.verifyTOTP` no longer answers "the MFA requirement is satisfied".** It
  now answers only "is this code valid and unspent", and is `false` when no secret is
  enrolled or the code is blank. The old lenient contract moved to `isMFASatisfied`.
  Callers that used `verifyTOTP` as a sole gate were relying on it returning `true` for an
  account with no MFA; they now fail closed.
- **One-time passwords are single-use by default.** A code that has verified is claimed
  and will not verify again for two minutes. Opt out with
  `Credentialed.setTOTPReplayGuard(TOTPReplayGuard.PERMISSIVE)`.

### Fixed

- **`0.1.0` could not read legacy records written under a non-ASCII secret on a non-UTF-8
  host.** It reproduced the pre-KDF XOR fold from `secret.getBytes(UTF_8)`, but `0.0.2`
  wrote them using `secret.getBytes()` — the platform default. Both candidates are now
  derived and tried, so strictly more records decrypt than before and nothing that
  decrypted stops. **Anyone who upgraded to `0.1.0` with a non-ASCII `globalSecret` should
  take this release before assuming those records are lost.**
- **`setGlobalSecret("")` threw `ArithmeticException`** — `i % buf.length` with a
  zero-length secret — after assigning the current key and before assigning the legacy
  one, leaving the class in a mixed state. It is now accepted, with a warning, and yields
  no legacy candidate.
- **`sign` and `verifySig` hashed platform-default-encoded bytes.** Now UTF-8 explicitly.
  This is a live path: under AXB-SIG-REQ the signed message is browser-produced JSON
  containing an email address, and a browser always signs UTF-8, so an account with a
  non-ASCII address could not authenticate on a non-UTF-8 host. The failure looked exactly
  like a wrong password.
- **`migrateCredentialFormat` was not atomic.** A failure on the MFA secret left the
  private key already rewritten in memory, with nothing to say so.
- **`SessionEngine` reused a GCM key and nonce for every token minted in the same
  second.** That leaks the XOR of the encrypted UUIDs — two users signing in during one
  second each expose the other's ID — and permits GHASH subkey recovery, hence tag
  forgery, hence minting a valid session key for an arbitrary user. A complete
  authentication bypass, which is why no legacy read path was kept.
- `verifySig` logged at ERROR on input taken straight off the wire, so any caller could
  flood the log with malformed Base64. Now debug.
- A null or wrong-length public key returns `false` explicitly instead of throwing an NPE
  inside a catch-all and logging it as a cryptographic error.
- `Security.addProvider` ran on every construction — global synchronized JVM state on a
  hot path, since consumers subclass `Credentialed` and build one per database row. Now a
  static initialiser.
- The static key fields were written under `synchronized` and read without it. They are
  now one `volatile` record, so a rotation publishes every key together.

### Changed

- `isLegacyFormat` and `decrypt` shared a single pass instead of running up to three trial
  decryptions per field. `isLegacyFormat` keeps its signature; its javadoc now states what
  a `true` actually means — *this cannot be read as a current-format record* — which also
  covers corrupt records and records under a different secret.
- The javadoc reference to `CredentialMigrator` is gone. No such class existed here or in
  any consumer; sweeping stored records needs database access and belongs to the consumer.
- `SessionEngine`'s format is now `[0x01][12-byte random nonce][GCM(issuedAt || uuid) ||
  tag]`, with the version byte authenticated as associated data and expiry read from the
  authenticated plaintext — one cipher operation per verification rather than a trial
  decryption per candidate second.
- Build pins `UTF-8` for compilation, javadoc and test execution. A new `charsetTest` task
  re-runs the charset-sensitive suite under `-Dfile.encoding=US-ASCII`, because under a
  UTF-8 default those tests pass whether or not the code pins its charsets.
- Dropped EasyMock (unused, and 4.3 cannot proxy classes on JDK 17+); TestNG 7.4.0 →
  7.11.0.

## 0.1.0

Random GCM nonce per encryption, HKDF-derived global secret, versioned record format, and
transparent reads of legacy fixed-IV records. Replaced the previous scheme, which used the
account UUID as the IV — fixed, public, and identical for both values stored against an
account — and which silently returned credential material unencrypted when no secret was
configured.

Note that the legacy-read path in this release is charset-dependent and is fixed in
`0.2.0`; see above.

## 0.0.2

Added a protected ID setter for `Credentialed`.

## 0.0.1

Initial release.
