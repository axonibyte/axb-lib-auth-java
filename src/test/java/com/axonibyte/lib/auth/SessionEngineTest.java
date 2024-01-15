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

/**
 * Test class to test {@link SessionEngine}.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class SessionEngineTest {

  /**
   * Assert that a session key can be verified and that the user's identifier
   * can be retrieved from the session key.
   *
   * @throws CryptoException if a cryptographic error occurs whilst generating
   *         new session key
   */
  @Test public void test_veriySessionKey_success() throws CryptoException {
    final String sessionSecret = "foo bar baz";
    final UUID userID = UUID.randomUUID();
    
    final SessionEngine sessionEngine_1 = new SessionEngine(sessionSecret, 2);
    final String sessionKey = sessionEngine_1.generateSessionKey(userID);

    final SessionEngine sessionEngine_2 = new SessionEngine(sessionSecret, 2);
    Assert.assertEquals(userID, sessionEngine_2.verifySessionKey(sessionKey));
  }
  
}
