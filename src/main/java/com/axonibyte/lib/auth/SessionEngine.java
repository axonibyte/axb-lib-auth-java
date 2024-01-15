/*
 * Copyright (c) 2022-2024 Axonibyte Innovations, LLC. All rights reserved.
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
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An engine that assists in the generation and verification of session keys.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class SessionEngine {

  private static final Logger logger = LoggerFactory.getLogger(SessionEngine.class);

  private byte[] secret = new byte[32];
  private int gracePeriod = 1;

  /**
   * Instantiates a new {@link SessionEngine}.
   *
   * @param secret the system secret used to encrypt session keys
   * @param gracePeriod the number of minutes during which a session key remains valid
   */
  public SessionEngine(String secret, int gracePeriod) {
    Security.addProvider(new BouncyCastleProvider());
    if(null != secret) {
      byte[] buf = secret.getBytes();
      for(int i = 0; i < (this.secret.length > buf.length ? this.secret.length : buf.length); i++)
        this.secret[i % this.secret.length] ^= buf[i % buf.length];
    }
    this.gracePeriod = gracePeriod;
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
    long now = System.currentTimeMillis() / 1000L;

    try {
      var key = new SecretKeySpec(this.secret, "AES");
      var iv = new IvParameterSpec(toIV(now, gracePeriod));
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      ByteBuffer userBuf = ByteBuffer.wrap(new byte[16]);
      userBuf.putLong(user.getMostSignificantBits());
      userBuf.putLong(user.getLeastSignificantBits());

      return new String(
          Base64.encode(
              cipher.doFinal(userBuf.array())));
      
    } catch(Exception e) {
      throw new CryptoException("failed to encrypt session key", e);
    }
  }

  /**
   * Verifies a particular session key.
   *
   * @param session the session key
   * @return a {@link UUID} associated with a user, if the session was valid, or
   *         {@code null} if the session could not be verified
   */
  public UUID verifySessionKey(String session) {
    long candidate = System.currentTimeMillis() / 1000L;
    UUID user = null;

    try {
      var key = new SecretKeySpec(secret, "AES");
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      byte[] ciphertext = Base64.decode(session.getBytes());
      for(int i = 0; i < gracePeriod && null == user; i++) {
        try {
          var iv = new IvParameterSpec(toIV(candidate - i, gracePeriod));
          cipher.init(Cipher.DECRYPT_MODE, key, iv);
          ByteBuffer byteBuf = ByteBuffer.wrap(cipher.doFinal(ciphertext));
          user = new UUID(byteBuf.getLong(), byteBuf.getLong());
        } catch(Exception e) { }
      }
    } catch(Exception e) {
      logger.error(
          "failed to decrypt provided session key: {}",
          null == e.getMessage() ? "no further info available" : e.getMessage());
    }

    return user;
  }

  /**
   * In short, this method is used to deterministically create a reproducable IV
   * from some long value (presumably a timestamp) and some integer value
   * (presumably the grace period). The signed long value `a` is encoded to the
   * first 8 bytes of a 12-byte array, in order such that index 0 holds the most
   * significant byte of `a` and index 7 holds the least significant byte of `a`.
   * Then, each byte of the array undergoes an XOR operion with each byte of
   * integer `b` in a reverse round-robin fashion. The resulting IV is sufficient
   * to guarantee a unique ID for every combination of values for `a` and `b`.
   */
  private byte[] toIV(long a, int b) {
    byte[] iv = new byte[12];
    for(int i = 7; i >= 0; i--) {
      iv[i] = (byte)(a & 0xFF);
      a >>= 8;
    }
    for(int i = 11; i >= 0; i--)
      iv[i] = (byte)(iv[i] ^ b >> i % 3 * 8);
    return iv;
  }

}
