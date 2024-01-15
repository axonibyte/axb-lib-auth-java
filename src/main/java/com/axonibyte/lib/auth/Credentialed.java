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
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
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
  
  private static byte[] globalSecret = new byte[32];

  /**
   * Sets the global secret used to encrypt MFA keys in the database.
   *
   * param secret the string representation of the MFA secret
   */
  public static synchronized void setGlobalSecret(String secret) {
    if(null == secret) {
      Credentialed.globalSecret = null;
      return;
    }
    
    byte[] buf = secret.getBytes();
    byte[] globalSecret = new byte[32];
    for(int i = 0; i < (globalSecret.length > buf.length ? globalSecret.length : buf.length); i++)
      globalSecret[i % globalSecret.length] ^= buf[i % buf.length];
    Credentialed.globalSecret = globalSecret;
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
    if(null == globalSecret)
      return datum;
    
    try {
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      var key = new SecretKeySpec(globalSecret, "AES");

      ByteBuffer idBuf = ByteBuffer.wrap(new byte[16]);
      idBuf.putLong(id.getMostSignificantBits());
      idBuf.putLong(id.getLeastSignificantBits());
      var iv = new IvParameterSpec(idBuf.array());

      cipher.init(encrypt ? Cipher.ENCRYPT_MODE: Cipher.DECRYPT_MODE, key, iv);
      return cipher.doFinal(datum);
    } catch(Exception e) {
      throw new CryptoException(
          String.format(
              "Failed to %1$s user secret (%2$s)",
              encrypt ? "encrypt" : "decrypt",
              null == e.getMessage() ? "no further info available" : e.getMessage()),
          e);
    }
  }
  
}
