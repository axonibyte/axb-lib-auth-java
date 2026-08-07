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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.util.encoders.Base64;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests the session key format.
 *
 * <p>Most of these pin properties the previous implementation did not have. It derived
 * the GCM nonce from the current epoch second, so two keys minted in the same second
 * reused a key and a nonce; it XOR-folded its secret, so {@code "A".repeat(64)} and any
 * other repeated 32-byte block collapsed to an all-zero AES key; it accepted a null
 * secret and ran on all zeros without complaint; and its validity was documented in
 * minutes but stepped in seconds.</p>
 *
 * @author Caleb L. Power &lt;cpower@axonibyte.com&gt;
 */
public class SessionEngineTest {

  private static final String SECRET = "correct horse battery staple";
  private static final Duration VALIDITY = Duration.ofMinutes(2);

  /** A clock the test moves by hand, so expiry needs no sleeping. */
  private static final class Movable extends Clock {
    private Instant now = Instant.parse("2026-01-01T00:00:00Z");

    @Override public Instant instant() {
      return now;
    }

    @Override public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    void advance(Duration by) {
      now = now.plus(by);
    }
  }

  @Test public void roundTrips_underTheSameSecret() throws Exception {
    var engine = new SessionEngine(SECRET, VALIDITY);
    UUID user = UUID.randomUUID();

    Assert.assertEquals(engine.verifySessionKey(engine.generateSessionKey(user)), user);
  }

  @Test public void differentSecret_doesNotVerify() throws Exception {
    UUID user = UUID.randomUUID();
    String key = new SessionEngine(SECRET, VALIDITY).generateSessionKey(user);

    Assert.assertNull(new SessionEngine("an entirely different secret", VALIDITY)
        .verifySessionKey(key));
  }

  @Test public void sameUserSameInstant_producesDifferentKeys() throws Exception {
    // The original defect. With the IV derived from the clock, these two calls produced
    // byte-identical strings -- and, worse, two *different* users in the same second were
    // encrypted under the same key and nonce, which leaks the XOR of their UUIDs and
    // permits GHASH subkey recovery.
    var clock = new Movable();
    var engine = new SessionEngine(SECRET, VALIDITY, clock);
    UUID user = UUID.randomUUID();

    Assert.assertNotEquals(
        engine.generateSessionKey(user),
        engine.generateSessionKey(user),
        "two keys minted at the same instant must not be identical");
  }

  @Test public void everyKeyDrawsAFreshNonce() throws Exception {
    var clock = new Movable();
    var engine = new SessionEngine(SECRET, VALIDITY, clock);
    UUID user = UUID.randomUUID();

    Set<String> nonces = new HashSet<>();
    for(int i = 0; i < 100; i++)
      nonces.add(
          Arrays.toString(
              Arrays.copyOfRange(Base64.decode(engine.generateSessionKey(user)), 1, 13)));

    Assert.assertEquals(nonces.size(), 100, "every encryption must draw a fresh nonce");
  }

  @Test public void validityIsHonouredInTheUnitItIsExpressedIn() throws Exception {
    // The old signature took an int documented as minutes, but verification walked back
    // one *second* per iteration -- so a caller asking for 2 got two seconds. Advancing
    // 90 seconds inside a two-minute window would have failed there and must pass here.
    var clock = new Movable();
    var engine = new SessionEngine(SECRET, Duration.ofMinutes(2), clock);
    UUID user = UUID.randomUUID();

    String key = engine.generateSessionKey(user);
    clock.advance(Duration.ofSeconds(90));

    Assert.assertEquals(engine.verifySessionKey(key), user);
  }

  @Test public void keyWithinValidity_isAccepted() throws Exception {
    var clock = new Movable();
    var engine = new SessionEngine(SECRET, VALIDITY, clock);
    UUID user = UUID.randomUUID();

    String key = engine.generateSessionKey(user);
    clock.advance(VALIDITY.minusMillis(1));

    Assert.assertEquals(engine.verifySessionKey(key), user);
  }

  @Test public void expiredKey_isRejected() throws Exception {
    var clock = new Movable();
    var engine = new SessionEngine(SECRET, VALIDITY, clock);
    UUID user = UUID.randomUUID();

    String key = engine.generateSessionKey(user);
    clock.advance(VALIDITY);

    Assert.assertNull(engine.verifySessionKey(key), "the window is half-open");
  }

  @Test public void futureDatedKey_isRejected() throws Exception {
    // Otherwise a key forged or replayed with a distant timestamp never expires.
    var issuer = new Movable();
    issuer.advance(Duration.ofHours(1));
    UUID user = UUID.randomUUID();
    String key = new SessionEngine(SECRET, VALIDITY, issuer).generateSessionKey(user);

    Assert.assertNull(new SessionEngine(SECRET, VALIDITY, new Movable()).verifySessionKey(key));
  }

  @Test public void tamperedKey_isRejected() throws Exception {
    var engine = new SessionEngine(SECRET, VALIDITY);
    UUID user = UUID.randomUUID();
    byte[] blob = Base64.decode(engine.generateSessionKey(user));

    for(int index : new int[] { 0, 5, 20, blob.length - 1 }) {
      byte[] tampered = Arrays.copyOf(blob, blob.length);
      tampered[index] ^= 0x01;
      Assert.assertNull(
          engine.verifySessionKey(
              new String(Base64.encode(tampered), java.nio.charset.StandardCharsets.US_ASCII)),
          "a bit flip at offset " + index + " must not verify");
    }
  }

  @Test public void repeatedSecretBlock_doesNotCollapseToAZeroKey() throws Exception {
    // Under the XOR fold, any secret made of a repeated 32-byte block folded to all
    // zeros -- so these two engines shared a key and each verified the other's tokens.
    var first = new SessionEngine("A".repeat(64), VALIDITY);
    var second = new SessionEngine("B".repeat(64), VALIDITY);

    Assert.assertNull(second.verifySessionKey(first.generateSessionKey(UUID.randomUUID())));
  }

  @Test public void nullOrEmptySecret_isRefusedAtConstruction() {
    // Previously a null secret left the key as new byte[32] and derivation was skipped
    // entirely: an all-zero AES key, silently.
    Assert.assertThrows(
        IllegalArgumentException.class, () -> new SessionEngine(null, VALIDITY));
    Assert.assertThrows(
        IllegalArgumentException.class, () -> new SessionEngine("", VALIDITY));
  }

  @Test public void nonPositiveValidity_isRefusedAtConstruction() {
    Assert.assertThrows(
        IllegalArgumentException.class, () -> new SessionEngine(SECRET, Duration.ZERO));
    Assert.assertThrows(
        IllegalArgumentException.class,
        () -> new SessionEngine(SECRET, Duration.ofMinutes(-1)));
  }

  @Test public void malformedInput_returnsNullRatherThanThrowing() {
    var engine = new SessionEngine(SECRET, VALIDITY);

    Assert.assertNull(engine.verifySessionKey(null));
    Assert.assertNull(engine.verifySessionKey(""));
    Assert.assertNull(engine.verifySessionKey("   "));
    Assert.assertNull(engine.verifySessionKey("not base64!!"));
    Assert.assertNull(engine.verifySessionKey("AAAA"));
  }

}
