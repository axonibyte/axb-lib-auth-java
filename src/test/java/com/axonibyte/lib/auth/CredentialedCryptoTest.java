/*
 * Copyright (c) 2026 Axonibyte Innovations, LLC. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.axonibyte.lib.auth;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Tests at-rest encryption of credential material.
 *
 * <p>The previous implementation used the account UUID as the AES-GCM IV. Since that
 * value is fixed, public, and shared between the two secrets stored against an
 * account, the private key and the TOTP secret were encrypted under the same key and
 * the same nonce -- which leaks their XOR and permits GHASH subkey recovery. These
 * tests pin the properties that prevent a regression.</p>
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class CredentialedCryptoTest {

  private static final String SECRET = "correct horse battery staple";

  @BeforeMethod public void setUp() {
    Security.addProvider(new BouncyCastleProvider());
    Credentialed.setGlobalSecret(SECRET);
  }

  private static Credentialed freshUser(UUID id) throws CryptoException {
    var user = new Credentialed(id, null, null, null);
    user.regenerateKeypair();
    user.regenerateMFAKey();
    return user;
  }

  @Test public void encryption_usesADistinctNonceForEachValue() throws Exception {
    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    byte[] privkey = user.getEncPrivkey();
    byte[] mfakey = user.getEncMFASecret();

    // Both blobs are [version][12-byte IV][ciphertext||tag]. The IVs must differ:
    // reusing one across two plaintexts under the same key is the original defect.
    byte[] privIV = Arrays.copyOfRange(privkey, 1, 13);
    byte[] mfaIV = Arrays.copyOfRange(mfakey, 1, 13);

    Assert.assertFalse(
        Arrays.equals(privIV, mfaIV),
        "private key and MFA secret must not share a GCM nonce");
  }

  @Test public void encryption_nonceIsNotDerivedFromTheAccountID() throws Exception {
    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    ByteBuffer idBuf = ByteBuffer.wrap(new byte[16]);
    idBuf.putLong(id.getMostSignificantBits());
    idBuf.putLong(id.getLeastSignificantBits());
    byte[] idBytes = idBuf.array();

    byte[] iv = Arrays.copyOfRange(user.getEncPrivkey(), 1, 13);

    Assert.assertFalse(
        Arrays.equals(iv, Arrays.copyOf(idBytes, 12)),
        "nonce must not be derived from the (public, fixed) account ID");
  }

  @Test public void encryption_repeatedEncryptionOfSameValueProducesDistinctNonces()
      throws Exception {
    // Re-keying an account must not reuse a nonce either.
    UUID id = UUID.randomUUID();
    var user = new Credentialed(id, null, null, null);

    Set<String> nonces = new HashSet<>();
    for(int i = 0; i < 25; i++) {
      user.regenerateKeypair();
      nonces.add(Arrays.toString(Arrays.copyOfRange(user.getEncPrivkey(), 1, 13)));
    }

    Assert.assertEquals(nonces.size(), 25, "every encryption must draw a fresh nonce");
  }

  @Test public void encryption_roundTripsThroughSignAndVerify() throws Exception {
    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    // sign() decrypts the private key internally, so a successful verify proves the
    // encrypt/decrypt round trip preserved the key exactly.
    String signature = user.sign("a message worth signing");
    Assert.assertTrue(user.verifySig("a message worth signing", signature));
  }

  @Test public void decryption_rejectsTamperedCiphertext() throws Exception {
    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    byte[] blob = user.getEncPrivkey();
    blob[blob.length - 1] ^= 0x01; // flip a bit in the authentication tag

    var tampered = new Credentialed(id, null, blob, null);
    Assert.assertThrows(CryptoException.class, () -> tampered.sign("x"));
  }

  @Test public void decryption_readsLegacyFixedIVRecords() throws Exception {
    // Stored data written before this change must remain readable, otherwise the
    // upgrade silently destroys every account's credentials.
    UUID id = UUID.randomUUID();
    byte[] plaintext = new byte[32];
    Arrays.fill(plaintext, (byte)0x5A);

    byte[] legacyBlob = legacyEncrypt(id, plaintext, SECRET);

    var user = new Credentialed(id, null, legacyBlob, null);
    Assert.assertTrue(
        user.isLegacyFormat(user.getEncPrivkey()),
        "a legacy record should be recognised as such");

    Assert.assertTrue(user.migrateCredentialFormat(), "migration should report work done");

    byte[] migrated = user.getEncPrivkey();
    Assert.assertFalse(
        user.isLegacyFormat(migrated),
        "record should be in the current format after migration");
    Assert.assertEquals(migrated[0], 0x01, "migrated record should carry the version marker");
  }

  @Test public void migration_isIdempotent() throws Exception {
    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    Assert.assertFalse(
        user.migrateCredentialFormat(),
        "already-current records need no migration");
  }

  @Test public void globalSecret_isStretchedRatherThanXORFolded() throws Exception {
    // The old derivation XOR-folded the raw bytes, so any secret consisting of a
    // repeated 32-byte block collapsed to an all-zero key. Under HKDF it does not.
    String pathological = "A".repeat(64); // folds to all zeros under the old scheme
    Credentialed.setGlobalSecret(pathological);

    UUID id = UUID.randomUUID();
    var user = freshUser(id);

    String sig = user.sign("still works");
    Assert.assertTrue(user.verifySig("still works", sig));

    // And a different secret must yield a different key, which the old scheme could
    // not guarantee for this family of inputs.
    byte[] underFirst = user.getEncPrivkey();
    Credentialed.setGlobalSecret("B".repeat(64));
    var other = new Credentialed(id, null, underFirst, null);
    Assert.assertThrows(CryptoException.class, () -> other.sign("x"));
  }

  @Test public void emptySecret_isAcceptedRatherThanThrowingArithmeticException() throws Exception {
    // The legacy XOR fold indexed buf[i % buf.length], so a zero-length secret divided by
    // zero -- and did so *after* the current key had already been assigned, leaving the
    // class holding a fresh key beside a stale legacy one. In yasss it surfaced as
    // "Failed to properly launch: / by zero", which names nothing useful.
    Credentialed.setGlobalSecret("");

    UUID id = UUID.randomUUID();
    var user = freshUser(id);
    Assert.assertTrue(user.verifySig("still works", user.sign("still works")));
  }

  @Test public void emptySecret_leavesNoLegacyKeyToDecryptWith() throws Exception {
    // Nothing can have been written under an empty secret, because the old code threw
    // before it could store anything. So there is deliberately no legacy candidate, and
    // a legacy blob must fail rather than be attempted against some improvised key.
    UUID id = UUID.randomUUID();
    byte[] legacyBlob = legacyEncrypt(id, new byte[32], SECRET);

    Credentialed.setGlobalSecret("");

    var user = new Credentialed(id, null, legacyBlob, null);
    Assert.assertThrows(CryptoException.class, () -> user.sign("x"));
  }

  @Test public void legacyRecords_areReadUnderThePlatformDefaultCharset() throws Exception {
    // 0.0.2 folded secret.getBytes() with no charset. Reproducing that from UTF-8 alone
    // would strand every stored record on a host whose default is something else and
    // whose secret is not ASCII. This passes trivially on a UTF-8 host -- charsetTest is
    // where it has teeth. See CredentialedCharsetTest.
    final String nonAscii = "pässwörd";
    UUID id = UUID.randomUUID();
    byte[] plaintext = new byte[32];
    Arrays.fill(plaintext, (byte)0x5A);

    byte[] legacyBlob = legacyEncrypt(
        id, plaintext, nonAscii.getBytes(java.nio.charset.Charset.defaultCharset()));

    Credentialed.setGlobalSecret(nonAscii);
    var user = new Credentialed(id, null, legacyBlob, null);

    Assert.assertTrue(user.migrateCredentialFormat(), "the legacy record should be readable");
  }

  @Test public void noGlobalSecret_failsClosedRatherThanStoringPlaintext() {
    // Previously this returned the datum untouched, writing private keys and TOTP
    // secrets to storage in the clear.
    Credentialed.setGlobalSecret(null);

    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    Assert.assertThrows(CryptoException.class, () -> user.regenerateKeypair());
  }

  /** Reproduces the pre-migration on-disk format: AES-GCM, XOR-folded key, UUID as IV. */
  private static byte[] legacyEncrypt(UUID id, byte[] plaintext, String secret)
      throws Exception {
    return legacyEncrypt(
        id, plaintext, secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  /**
   * As above, but over raw secret bytes, so a test can pin which charset produced them.
   * 0.0.2 used {@code secret.getBytes()} -- the platform default -- so that distinction
   * is the whole point of the dual-candidate legacy derivation.
   */
  private static byte[] legacyEncrypt(UUID id, byte[] plaintext, byte[] buf)
      throws Exception {
    byte[] key = new byte[32];
    for(int i = 0; i < Math.max(key.length, buf.length); i++)
      key[i % key.length] ^= buf[i % buf.length];

    ByteBuffer idBuf = ByteBuffer.wrap(new byte[16]);
    idBuf.putLong(id.getMostSignificantBits());
    idBuf.putLong(id.getLeastSignificantBits());

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(idBuf.array()));
    return cipher.doFinal(plaintext);
  }

}
