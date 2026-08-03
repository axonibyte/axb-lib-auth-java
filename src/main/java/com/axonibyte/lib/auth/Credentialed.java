/*
 * Copyright (c) 2023-2024 Axonibyte Innovations, LLC. All rights reserved.
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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

/**
 * Represents a user or other entity that needs the ability to authenticate with
 * the system.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class Credentialed {

  private static final Logger logger = LoggerFactory.getLogger(Credentialed.class);
  
  /** Marks a blob written with the random-IV format. */
  private static final byte FORMAT_VERSION = 0x01;

  /** Standard GCM nonce length. */
  private static final int GCM_IV_BYTES = 12;

  /** GCM authentication tag length, in bits. */
  private static final int GCM_TAG_BITS = 128;

  /**
   * HKDF salt. A fixed, non-secret value is fine here: HKDF's salt provides domain
   * separation, not secrecy, and all of the entropy comes from the configured secret.
   * It must stay stable or previously-derived keys stop matching.
   */
  private static final byte[] KDF_SALT =
      "axb-lib-auth:credentialed".getBytes(StandardCharsets.UTF_8);

  /** HKDF info parameter, binding the derived key to this specific usage. */
  private static final byte[] KDF_INFO =
      "at-rest-key:v1".getBytes(StandardCharsets.UTF_8);

  private static final SecureRandom RANDOM = new SecureRandom();

  private static byte[] globalSecret = null;

  /**
   * The key derived the old way (XOR-folding the raw secret bytes). Retained solely so
   * that records written before the KDF change can still be read and re-encrypted; it
   * is never used to write.
   */
  private static byte[] legacyGlobalSecret = null;

  /**
   * Sets the global secret used to encrypt private keys and MFA secrets at rest.
   *
   * <p>The secret is stretched with HKDF-SHA256. The previous implementation XOR-folded
   * the raw bytes into 32 bytes, which meant a short passphrase produced a 256-bit AES
   * key carrying only as much entropy as the passphrase had bytes, a 64-byte secret
   * halved its own entropy, and any secret consisting of a repeated 32-byte block
   * folded to all zeros.</p>
   *
   * @param secret the secret; {@code null} clears it, after which encryption and
   *        decryption both fail rather than silently passing data through
   */
  public static synchronized void setGlobalSecret(String secret) {
    if(null == secret) {
      Credentialed.globalSecret = null;
      Credentialed.legacyGlobalSecret = null;
      return;
    }

    byte[] buf = secret.getBytes(StandardCharsets.UTF_8);

    var hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(buf, KDF_SALT, KDF_INFO));
    byte[] derived = new byte[32];
    hkdf.generateBytes(derived, 0, derived.length);
    Credentialed.globalSecret = derived;

    // Reproduce the legacy derivation so pre-existing records remain readable.
    byte[] legacy = new byte[32];
    for(int i = 0; i < Math.max(legacy.length, buf.length); i++)
      legacy[i % legacy.length] ^= buf[i % buf.length];
    Credentialed.legacyGlobalSecret = legacy;
  }
  
  private UUID id = null;
  private byte[] pubkey = null;
  private byte[] privkey = null;
  private byte[] mfakey = null;

  /**
   * Instantiates a credentialed user.
   *
   * @param id the user's unique identifier
   * @param pubkey the user's public key
   * @param privkey the user's private key
   * @param mfakey the user's encrypted mfakey
   */
  public Credentialed(UUID id, byte[] pubkey, byte[] privkey, byte[] mfakey) {
    Security.addProvider(new BouncyCastleProvider());
    this.id = id;
    this.pubkey = pubkey;
    this.privkey = privkey;
    this.mfakey = mfakey;
  }

  /**
   * Retrieves the unique identifier associated with this user.
   *
   * @return the user's {@link UUID}
   */
  public UUID getID() {
    return id;
  }

  /**
   * Sets the ID of the credentialed user.
   *
   * @param id the user's unique identifier
   */
  protected void setID(UUID id) {
    this.id = id;
  }

  /**
   * Retrieves the user's public key.
   *
   * @return a byte array representing the user's public key
   */
  public byte[] getPubkey() {
    return null == pubkey ? null : Arrays.copyOf(pubkey, pubkey.length);
  }

  /**
   * Retrieves the user's private key, encrypted.
   *
   * @return a byte array representing the user's private key
   */
  public byte[] getEncPrivkey() {
    return null == privkey ? null : Arrays.copyOf(privkey, privkey.length);
  }

  /**
   * Retrieves the user's MFA secret, encrypted.
   *
   * @return a byte array representing the user's encrypted MFA secret
   */
  public byte[] getEncMFASecret() {
    return null == mfakey ? null : Arrays.copyOf(mfakey, mfakey.length);
  }

  /**
   * Verifies a message and signature against this user's public key to ensure
   * that this user is responsible for sending the message.
   *
   * @param message the message data itself
   * @param sig the message signature
   * @return true iff the signature is valid and verified
   */
  public boolean verifySig(String message, String sig) {
    try {
      byte[] msgBuf = message.getBytes();
      byte[] sigBuf = Base64.decode(sig);
    
      Signer verifier = new Ed25519Signer();
      verifier.init(false, new Ed25519PublicKeyParameters(this.pubkey));
      verifier.update(msgBuf, 0, msgBuf.length);
      return verifier.verifySignature(sigBuf);
    } catch(Exception e) {
      logger.error(
          "cyptographic error occured whilst verifying signature: {}",
          null == e.getMessage() ? "no further info available" : e.getMessage());
      return false;
    }
  }

  /**
   * Signs a message with the user's private key, if it exists.
   *
   * @param message the message data to be signed
   * @return a Base64-encoded signature
   * @throws CryptoException if the private key could not be decrypted for signing
   */
  public String sign(String message) throws CryptoException {
    if(null == privkey) return "";
    byte[] msgBuf = message.getBytes();

    try {
      Signer signer = new Ed25519Signer();
      signer.init(
          true,
          new Ed25519PrivateKeyParameters(
              cryptop(this.privkey, false)));
      signer.update(msgBuf, 0, msgBuf.length);
      return new String(Base64.encode(signer.generateSignature()));
    } catch(Exception e) {
      throw new CryptoException("failed to sign message", e);
    }
  }

  /**
   * Sets the public key associated with this user.
   *
   * @param pubkey the Base64 representation of the public key
   * @throws CryptoException if the pubkey was not a valid Base64 representation
   */
  public void setPubkey(String pubkey) throws CryptoException {
    try {
      this.pubkey = Base64.decode(pubkey);
    } catch(DecoderException e) {
      throw new CryptoException("pubkey was not represented by valid Base64", e);
    }
  }

  /**
   * Verifies a TOTP provided by the user.
   *
   * @return true if the TOTP is verified
   */
  public boolean verifyTOTP(String totp) {
    if(null == this.mfakey && (null == totp || totp.isBlank())) return true;
    if(null == this.mfakey) return false;
    
    final TimeProvider timeProvider = new SystemTimeProvider();
    final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    try {
      return verifier.isValidCode(
          new String(
              Base32.encode(
                  cryptop(this.mfakey, false))),
          totp);
    } catch(CryptoException e) {
      logger.error(
          "MFA key decryption failed: {}",
          null == e.getMessage() ? "no further info available" : e.getMessage());
      return false;
    }
  }

  /**
   * Sets the user's MFA secret.
   *
   * @param mfakey the new MFA secret
   * @return true if the new MFA key is different than the old one
   * @throws CryptoException if the MFA key could not be decoded
   */
  public boolean setMFAKey(String mfakey) throws CryptoException {
    try {
    byte[] prev = this.mfakey;
    this.mfakey = null == mfakey ? null : cryptop(Base32.decode(mfakey), true);
    return null == prev && null != this.mfakey
      || null != prev && null == this.mfakey
      || !Arrays.equals(prev, this.mfakey);
    } catch(DecoderException e) {
      throw new CryptoException("could not decode MFA key", e);
    }
  }

  /**
   * Regenerates the user's MFA key.
   *
   * @return the string representation of the new MFA key
   * @throws CryptoException if the MFA key was badly generated
   */
  public String regenerateMFAKey() throws CryptoException {
    final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    String mfakey = secretGenerator.generate();
    setMFAKey(mfakey);
    return mfakey;
  }

  /**
   * Regenerates the user's private and public keys.
   *
   * @throws CryptoException if a cryptographic error occurred
   */
  public void regenerateKeypair() throws CryptoException {
    try {
      final Ed25519KeyPairGenerator keygen = new Ed25519KeyPairGenerator();
      keygen.init(new Ed25519KeyGenerationParameters(SecureRandom.getInstanceStrong()));
      var keypair = keygen.generateKeyPair();
      var privkey = new byte[32];
      ((Ed25519PrivateKeyParameters)keypair.getPrivate()).encode(privkey, 0);
      this.privkey = cryptop(privkey, true);
      this.pubkey = ((Ed25519PublicKeyParameters)keypair.getPublic()).getEncoded();
    } catch(Exception e) {
      throw new CryptoException("failed to generate a new keypair", e);
    }
  }

  private byte[] cryptop(byte[] datum, boolean encrypt) throws CryptoException {
    // Previously this returned the datum untouched when no secret was configured, which
    // silently wrote private keys and TOTP secrets to storage in plaintext. Fail instead.
    if(null == globalSecret)
      throw new CryptoException(
          "No global secret configured; refusing to handle credential material.", null);

    if(null == datum) return null;

    return encrypt ? encrypt(datum) : decrypt(datum);
  }

  /**
   * Encrypts credential material under a freshly-generated random nonce.
   *
   * <p>The output is {@code [version][12-byte IV][ciphertext||tag]}. The previous
   * implementation derived the GCM IV from the account UUID, which is fixed, public,
   * and identical for both values stored against an account -- so the private key and
   * the TOTP secret were encrypted under the same key and the same nonce. That leaks
   * the XOR of the two plaintexts and permits recovery of the GHASH subkey, which in
   * turn allows forging authentication tags.</p>
   */
  private byte[] encrypt(byte[] plaintext) throws CryptoException {
    try {
      byte[] iv = new byte[GCM_IV_BYTES];
      RANDOM.nextBytes(iv);

      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(globalSecret, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, iv));

      byte[] ciphertext = cipher.doFinal(plaintext);

      return ByteBuffer.allocate(1 + iv.length + ciphertext.length)
          .put(FORMAT_VERSION)
          .put(iv)
          .put(ciphertext)
          .array();

    } catch(Exception e) {
      throw new CryptoException(
          String.format(
              "Failed to encrypt user secret (%1$s)",
              null == e.getMessage() ? "no further info available" : e.getMessage()),
          e);
    }
  }

  /**
   * Decrypts credential material, transparently accepting records written in the
   * legacy fixed-IV format.
   *
   * <p>Format detection relies on GCM authentication rather than on the version byte
   * alone: legacy blobs are raw ciphertext and so may begin with any byte, including
   * the version marker. Interpreting a legacy blob as versioned therefore fails the
   * tag check, at which point the legacy path is tried. A genuine mismatch cannot slip
   * through, because both paths are authenticated.</p>
   */
  private byte[] decrypt(byte[] blob) throws CryptoException {
    if(blob.length > 1 + GCM_IV_BYTES && FORMAT_VERSION == blob[0]) {
      try {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(globalSecret, "AES"),
            new GCMParameterSpec(GCM_TAG_BITS, Arrays.copyOfRange(blob, 1, 1 + GCM_IV_BYTES)));
        return cipher.doFinal(blob, 1 + GCM_IV_BYTES, blob.length - 1 - GCM_IV_BYTES);
      } catch(Exception e) {
        // Not a current-format record after all; fall through and try the legacy path.
      }
    }

    return decryptLegacy(blob);
  }

  /**
   * Decrypts a record written before the random-IV change: AES-GCM under the
   * XOR-folded key, with the account UUID as the IV.
   *
   * <p>Retained only so stored credentials survive the upgrade. Re-saving the entity
   * rewrites it in the current format; see {@code CredentialMigrator}.</p>
   */
  private byte[] decryptLegacy(byte[] blob) throws CryptoException {
    if(null == legacyGlobalSecret)
      throw new CryptoException("No legacy secret available to decrypt this record.", null);
    if(null == id)
      throw new CryptoException("Legacy records require an entity ID to derive the IV.", null);

    try {
      ByteBuffer idBuf = ByteBuffer.wrap(new byte[16]);
      idBuf.putLong(id.getMostSignificantBits());
      idBuf.putLong(id.getLeastSignificantBits());

      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(legacyGlobalSecret, "AES"),
          new IvParameterSpec(idBuf.array()));

      byte[] plaintext = cipher.doFinal(blob);
      logger.warn(
          "Read a legacy fixed-IV credential record for {}; re-save it to migrate.", id);
      return plaintext;

    } catch(Exception e) {
      throw new CryptoException(
          String.format(
              "Failed to decrypt user secret (%1$s)",
              null == e.getMessage() ? "no further info available" : e.getMessage()),
          e);
    }
  }

  /**
   * Determines whether a stored blob is still in the legacy fixed-IV format and so
   * needs re-encryption.
   *
   * @param blob the stored credential material
   * @return {@code true} iff the blob predates the random-IV format
   */
  public boolean isLegacyFormat(byte[] blob) {
    if(null == blob || blob.length <= 1 + GCM_IV_BYTES || FORMAT_VERSION != blob[0])
      return true;
    try {
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(globalSecret, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, Arrays.copyOfRange(blob, 1, 1 + GCM_IV_BYTES)));
      cipher.doFinal(blob, 1 + GCM_IV_BYTES, blob.length - 1 - GCM_IV_BYTES);
      return false;
    } catch(Exception e) {
      return true;
    }
  }

  /**
   * Rewrites this entity's stored credential material in the current format, so that
   * legacy fixed-IV records are migrated in place.
   *
   * <p>Callers are responsible for persisting the entity afterwards; this only updates
   * the in-memory representation returned by {@link #getEncPrivkey()} and
   * {@link #getEncMFASecret()}.</p>
   *
   * @return {@code true} iff anything was rewritten
   * @throws CryptoException if the existing material could not be read
   */
  public boolean migrateCredentialFormat() throws CryptoException {
    boolean migrated = false;

    if(null != privkey && isLegacyFormat(privkey)) {
      privkey = encrypt(decrypt(privkey));
      migrated = true;
    }

    if(null != mfakey && isLegacyFormat(mfakey)) {
      mfakey = encrypt(decrypt(mfakey));
      migrated = true;
    }

    if(migrated)
      logger.info("Migrated credential material for {} to the random-IV format.", id);

    return migrated;
  }

}
