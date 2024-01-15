/*
 * Copyright (c) 2024 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
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

import java.util.UUID;

import org.testng.Assert;
import org.testng.annotations.Test;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

/**
 * Test class to test the {@link Credentialed} model.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class CredentialedTest {

  /**
   * Assert that a message can be signed by both a new Credentialed user and a
   * reconstructed Credentialed user when there is no global secret.
   *
   * @throws CryptoException if a cryptographic error occurred
   */
  @Test public void test_sign_noGlobalSecret() throws CryptoException {
    final String plaintext = "Hello, world!";
    final UUID credentialedID = UUID.randomUUID();

    Credentialed.setGlobalSecret(null);
    
    final Credentialed credentialed_1 = new Credentialed(credentialedID, null, null, null);
    credentialed_1.regenerateKeypair();
    final String sig_1 = credentialed_1.sign(plaintext);

    final Credentialed credentialed_2 = new Credentialed(
        credentialedID,
        credentialed_1.getPubkey(),
        credentialed_1.getEncPrivkey(),
        null);
    final String sig_2 = credentialed_2.sign(plaintext);

    Assert.assertEquals(sig_2, sig_1);
  }

  /**
   * Assert that a message can be signed by both a new Credentialed user and a
   * reconstructed Credentialed user when a global secret has been established.
   *
   * @throws CryptoException if a cryptographic error occurred
   */
  @Test public void test_sign_withGlobalSecret() throws CryptoException {
    final String plaintext = "Hello, world!";
    final UUID credentialedID = UUID.randomUUID();

    Credentialed.setGlobalSecret("foo bar baz");
    
    final Credentialed credentialed_1 = new Credentialed(credentialedID, null, null, null);
    credentialed_1.regenerateKeypair();
    final String sig_1 = credentialed_1.sign(plaintext);

    final Credentialed credentialed_2 = new Credentialed(
        credentialedID,
        credentialed_1.getPubkey(),
        credentialed_1.getEncPrivkey(),
        null);
    final String sig_2 = credentialed_2.sign(plaintext);

    Assert.assertEquals(sig_2, sig_1);
  }

  /**
   * Assert that a signature can be verified.
   *
   * @throws CryptoException if a cryptographic error occurred
   */
  @Test public void test_verifySig() throws CryptoException {
    final String plaintext = "Hello, world!";
    final UUID credentialedID = UUID.randomUUID();

    Credentialed.setGlobalSecret(null);

    final Credentialed credentialed_1 = new Credentialed(credentialedID, null, null, null);
    credentialed_1.regenerateKeypair();
    final String sig_1 = credentialed_1.sign(plaintext);

    final Credentialed credentialed_2 = new Credentialed(
        credentialedID,
        credentialed_1.getPubkey(),
        credentialed_1.getEncPrivkey(),
        null);

    Assert.assertTrue(
        credentialed_2.verifySig(
            plaintext,
            sig_1));
  }

  /**
   * Assert that a Credentialed user's provided MFA token can be verified.
   *
   * @throws CodeGenerationException if the test MFA code could not be generated
   * @throws CryptoException if a cryptographic error occurred
   */
  @Test public void test_verifyMFA() throws CodeGenerationException, CryptoException {
    final UUID credentialedID = UUID.randomUUID();
    
    final Credentialed credentialed_1 = new Credentialed(credentialedID, null, null, null);
    final String mfaSecret = credentialed_1.regenerateMFAKey();

    final Credentialed credentialed_2 = new Credentialed(
        credentialedID,
        null,
        null,
        credentialed_1.getEncMFASecret());

    final TimeProvider timeProvider = new SystemTimeProvider();
    final CodeGenerator codeGen = new DefaultCodeGenerator();

    final String code = codeGen.generate(mfaSecret, Math.floorDiv(timeProvider.getTime(), 30));
    Assert.assertTrue(credentialed_1.verifyTOTP(code));
    Assert.assertTrue(credentialed_2.verifyTOTP(code));
  }
  
}
