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

import java.util.UUID;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

/**
 * Covers one-time password verification: that a code is valid once, that "no MFA
 * enrolled" and "code accepted" are answered by different methods, and that a wrong guess
 * cannot spend a code the guesser does not have.
 *
 * @author Caleb L. Power &lt;cpower@axonibyte.com&gt;
 */
public class CredentialedTOTPTest {

  private static final String SECRET = "correct horse battery staple";

  @BeforeMethod public void setUp() {
    Credentialed.setGlobalSecret(SECRET);
    // Process-global, and every method here depends on starting from an empty one.
    Credentialed.setTOTPReplayGuard(null);
  }

  @AfterMethod public void tearDown() {
    Credentialed.setTOTPReplayGuard(null);
  }

  /** Generates the code currently valid for a freshly enrolled secret. */
  private static String currentCode(String mfaSecret) throws Exception {
    final TimeProvider time = new SystemTimeProvider();
    final CodeGenerator generator = new DefaultCodeGenerator();
    return generator.generate(mfaSecret, Math.floorDiv(time.getTime(), 30));
  }

  @Test public void aValidCodeIsAcceptedOnce() throws Exception {
    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    String code = currentCode(user.regenerateMFAKey());

    Assert.assertTrue(user.verifyTOTP(code), "the first presentation must be accepted");
  }

  @Test public void theSameCodeIsRefusedTheSecondTime() throws Exception {
    // The whole point. Without a record of spent codes, a captured AXB-SIG-REQ payload
    // for an MFA account stays replayable for as long as its embedded code is valid --
    // roughly ninety seconds, since the verifier allows a step either side.
    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    String code = currentCode(user.regenerateMFAKey());

    Assert.assertTrue(user.verifyTOTP(code));
    Assert.assertFalse(user.verifyTOTP(code), "a one-time password must be usable once");
  }

  @Test public void aCodeSpentOnOneInstanceIsSpentOnEveryInstanceOfTheSameEntity()
      throws Exception {
    // The guard is keyed on the entity, not the object. yasss builds a fresh Credentialed
    // per request out of User.fromRow, so a per-object record would protect nothing.
    UUID id = UUID.randomUUID();
    var first = new Credentialed(id, null, null, null);
    String code = currentCode(first.regenerateMFAKey());

    var second = new Credentialed(id, null, null, first.getEncMFASecret());

    Assert.assertTrue(first.verifyTOTP(code));
    Assert.assertFalse(second.verifyTOTP(code));
  }

  @Test public void twoEntitiesDoNotShareASlot() throws Exception {
    // A collision here would refuse a legitimate code, which is worse than the problem
    // being solved.
    var a = new Credentialed(UUID.randomUUID(), null, null, null);
    var b = new Credentialed(UUID.randomUUID(), null, null, null);

    String secret = a.regenerateMFAKey();
    b.setMFAKey(secret);
    String code = currentCode(secret);

    Assert.assertTrue(a.verifyTOTP(code));
    Assert.assertTrue(b.verifyTOTP(code), "another entity's claim must not spend this one");
  }

  @Test public void aWrongGuessDoesNotSpendTheSlot() throws Exception {
    // Claiming before verifying would let anyone burn a code by guessing it, and would
    // make the guard an oracle for which codes are in play.
    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    String code = currentCode(user.regenerateMFAKey());

    Assert.assertFalse(user.verifyTOTP("000000"), "a wrong code is refused");
    Assert.assertTrue(user.verifyTOTP(code), "and must not have consumed the real one");
  }

  @Test public void thePermissiveGuardAllowsReplay() throws Exception {
    // The documented opt-out for a deployment with its own replay protection.
    Credentialed.setTOTPReplayGuard(TOTPReplayGuard.PERMISSIVE);

    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    String code = currentCode(user.regenerateMFAKey());

    Assert.assertTrue(user.verifyTOTP(code));
    Assert.assertTrue(user.verifyTOTP(code));
  }

  @Test public void withNoSecretEnrolledThereIsNoValidCode() {
    // verifyTOTP used to answer true here, which is an authentication bypass for any
    // caller using it as the only gate.
    var user = new Credentialed(UUID.randomUUID(), null, null, null);

    Assert.assertFalse(user.verifyTOTP(null));
    Assert.assertFalse(user.verifyTOTP(""));
    Assert.assertFalse(user.verifyTOTP("123456"));
  }

  @Test public void withNoSecretEnrolledTheMFARequirementIsSatisfied() {
    // The lenient question, now asked separately. Note the old single method answered
    // false for the third case, so a caller that always forwarded whatever the client
    // sent rejected users who had no MFA but sent something anyway.
    var user = new Credentialed(UUID.randomUUID(), null, null, null);

    Assert.assertTrue(user.isMFASatisfied(null));
    Assert.assertTrue(user.isMFASatisfied(""));
    Assert.assertTrue(user.isMFASatisfied("123456"));
  }

  @Test public void withASecretEnrolledTheMFARequirementNeedsAValidCode() throws Exception {
    var user = new Credentialed(UUID.randomUUID(), null, null, null);
    String code = currentCode(user.regenerateMFAKey());

    Assert.assertFalse(user.isMFASatisfied(null));
    Assert.assertFalse(user.isMFASatisfied("000000"));
    Assert.assertTrue(user.isMFASatisfied(code));
  }

}
