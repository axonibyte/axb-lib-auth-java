/*
 * Copyright (c) 2022-2026 Axonibyte Innovations, LLC. All rights reserved.
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
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An engine that assists in the generation and verification of session keys.
 *
 * <p>A session key is an authenticated, self-expiring token naming a user. It carries its
 * own issue time inside the encrypted payload, so verification is one cipher operation
 * regardless of how long the validity window is.</p>
 *
 * <p><b>The previous format is not readable and is not meant to be.</b> It derived the
 * GCM nonce from the current epoch second, so every key minted in the same second, for
 * every user, reused one key and one nonce. Under GCM that leaks the XOR of the encrypted
 * UUIDs and permits recovery of the GHASH subkey, which is enough to forge an
 * authentication tag -- and therefore to mint a valid session key for an arbitrary user.
 * That is a complete authentication bypass rather than a weakening, so there is nothing
 * worth staying compatible with. Any key issued by an earlier version simply fails to
 * verify.</p>
 *
 * @author Caleb L. Power &lt;cpower@axonibyte.com&gt;
 */
public class SessionEngine {

  private static final Logger logger = LoggerFactory.getLogger(SessionEngine.class);

  static {
    // See Credentialed's static block: registering a provider is global synchronized JVM
    // state and does not belong in a constructor.
    Security.addProvider(new BouncyCastleProvider());
  }

  /** Marks the authenticated-payload format. */
  private static final byte FORMAT_VERSION = 0x01;

  /** Standard GCM nonce length. */
  private static final int GCM_IV_BYTES = 12;

  /** GCM authentication tag length, in bits. */
  private static final int GCM_TAG_BITS = 128;

  /** 8 bytes of issue time, then 16 of UUID. */
  private static final int PAYLOAD_BYTES = 24;

  /**
   * HKDF salt. Fixed and non-secret: the salt provides domain separation, not secrecy.
   */
  private static final byte[] KDF_SALT =
      "axb-lib-auth:session".getBytes(StandardCharsets.UTF_8);

  /**
   * HKDF info. Deliberately different from {@code Credentialed}'s, so that a deployment
   * configuring one passphrase for both does not end up using one key for both.
   */
  private static final byte[] KDF_INFO =
      "session-key:v1".getBytes(StandardCharsets.UTF_8);

  /**
   * How far ahead of us a key may claim to have been issued before we refuse it. Without
   * a bound, a key forged or replayed with a future timestamp would be valid indefinitely.
   */
  private static final long MAX_CLOCK_SKEW_MILLIS = 60_000L;

  private static final SecureRandom RANDOM = new SecureRandom();

  private final byte[] secret;
  private final long validityMillis;
  private final Clock clock;

  /**
   * Instantiates a new {@link SessionEngine}.
   *
   * <p>Note the second parameter is a {@link Duration}. It replaces an {@code int} that
   * was documented in minutes and implemented in seconds, so a caller following the
   * javadoc got a window sixty times shorter than it asked for. Changing the unit of an
   * {@code int} silently would have given such a caller a sixty-times-longer session with
   * no compile error and no runtime signal; removing the constructor makes it a build
   * failure instead, which is the notification this deserves.</p>
   *
   * @param secret the system secret from which the session key is derived
   * @param validity how long a session key remains valid after it is issued
   * @throws IllegalArgumentException if the secret is null or empty, or the validity is
   *         not positive
   */
  public SessionEngine(String secret, Duration validity) {
    this(secret, validity, Clock.systemUTC());
  }

  /**
   * As above, with an injectable clock so that expiry can be tested without sleeping.
   *
   * @param secret the system secret from which the session key is derived
   * @param validity how long a session key remains valid after it is issued
   * @param clock the clock to read the current time from
   */
  SessionEngine(String secret, Duration validity, Clock clock) {
    // Fails at construction rather than at first use. A session engine with no secret is
    // a configuration error, and the stack trace at startup names the caller that made
    // it. The previous implementation initialised its key to new byte[32] and skipped
    // derivation entirely when the secret was null, so a misconfigured deployment ran
    // happily on an all-zero AES key and said nothing.
    if(null == secret || secret.isEmpty())
      throw new IllegalArgumentException(
          "A session engine requires a non-empty secret; refusing to derive a key from nothing.");
    if(null == validity || validity.isNegative() || validity.isZero())
      throw new IllegalArgumentException("Session key validity must be a positive duration.");

    var hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(
        new HKDFParameters(secret.getBytes(StandardCharsets.UTF_8), KDF_SALT, KDF_INFO));
    this.secret = new byte[32];
    hkdf.generateBytes(this.secret, 0, this.secret.length);

    this.validityMillis = validity.toMillis();
    this.clock = Objects.requireNonNull(clock);
  }

  /**
   * Generates a session key for a particular user.
   *
   * @param user the {@link UUID} associated with the user in question
   * @return some string that the user can use to maintain their session
   * @throws CryptoException if a cryptographic error occurs
   */
  public String generateSessionKey(UUID user) throws CryptoException {
    Objects.requireNonNull(user);

    try {
      byte[] iv = new byte[GCM_IV_BYTES];
      RANDOM.nextBytes(iv);

      ByteBuffer payload = ByteBuffer.allocate(PAYLOAD_BYTES);
      payload.putLong(clock.millis());
      payload.putLong(user.getMostSignificantBits());
      payload.putLong(user.getLeastSignificantBits());

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(secret, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, iv));

      // The version byte travels in the clear but is authenticated as associated data, so
      // an attempt to rewrite it -- to point a future version at this one's parser -- fails
      // the tag check rather than being quietly reinterpreted.
      cipher.updateAAD(new byte[] { FORMAT_VERSION });

      byte[] ciphertext = cipher.doFinal(payload.array());

      return new String(
          Base64.encode(
              ByteBuffer.allocate(1 + iv.length + ciphertext.length)
                  .put(FORMAT_VERSION)
                  .put(iv)
                  .put(ciphertext)
                  .array()),
          StandardCharsets.US_ASCII);

    } catch(Exception e) {
      throw new CryptoException("failed to encrypt session key", e);
    }
  }

  /**
   * Verifies a particular session key.
   *
   * <p>Every failure -- malformed, tampered, expired, future-dated -- answers
   * {@code null} and logs at debug. The argument arrives from an untrusted caller, so a
   * failure here is an ordinary outcome and must not be a lever for writing log lines.</p>
   *
   * @param session the session key
   * @return a {@link UUID} associated with a user, if the session was valid, or
   *         {@code null} if the session could not be verified
   */
  public UUID verifySessionKey(String session) {
    if(null == session || session.isBlank()) return null;

    try {
      byte[] blob = Base64.decode(session);

      if(blob.length != 1 + GCM_IV_BYTES + PAYLOAD_BYTES + GCM_TAG_BITS / 8) return null;
      if(FORMAT_VERSION != blob[0]) return null;

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(secret, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, Arrays.copyOfRange(blob, 1, 1 + GCM_IV_BYTES)));
      cipher.updateAAD(new byte[] { FORMAT_VERSION });

      ByteBuffer payload = ByteBuffer.wrap(
          cipher.doFinal(blob, 1 + GCM_IV_BYTES, blob.length - 1 - GCM_IV_BYTES));

      // Read out of the authenticated plaintext, so it cannot be edited in transit. This
      // replaces a loop that re-derived an IV per candidate second and tried to decrypt
      // against each: with the validity honestly expressed in minutes that loop would
      // have run sixty trial decryptions per minute of window, per request, which is an
      // attacker-triggerable amount of work for a token that is going to fail anyway.
      long issuedAt = payload.getLong();
      long now = clock.millis();

      if(issuedAt > now + MAX_CLOCK_SKEW_MILLIS) {
        logger.debug("Refused a session key issued {}ms in the future.", issuedAt - now);
        return null;
      }

      if(now - issuedAt >= validityMillis) {
        logger.debug("Refused a session key that expired {}ms ago.", now - issuedAt - validityMillis);
        return null;
      }

      return new UUID(payload.getLong(), payload.getLong());

    } catch(Exception e) {
      logger.debug(
          "failed to decrypt provided session key: {}",
          null == e.getMessage() ? "no further info available" : e.getMessage());
      return null;
    }
  }

}
