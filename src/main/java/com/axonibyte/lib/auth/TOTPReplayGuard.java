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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Records which one-time passwords have already been spent, so that a captured code
 * cannot be presented twice.
 *
 * <p>A TOTP is valid for its whole time step, and the verifier allows a step either side
 * of the current one, so without a record of what has been used a six-digit code stays
 * good for roughly ninety seconds and can be replayed any number of times within that
 * window. That is the ordinary, accepted weakness of TOTP taken alone -- but under
 * AXB-SIG-REQ the credential payload is otherwise static, so for an account with MFA the
 * embedded code is the <em>only</em> thing bounding how long a captured
 * {@code Authorization} header remains usable. Without this, that bound is ninety
 * seconds rather than one use.</p>
 *
 * @author Caleb L. Power &lt;cpower@axonibyte.com&gt;
 */
public interface TOTPReplayGuard {

  /**
   * Claims a code for an entity, if it has not already been spent.
   *
   * <p>Implementations must be safe for concurrent use.</p>
   *
   * @param entity the entity the code was presented for
   * @param code the one-time password
   * @return {@code true} if the code was unused and is now claimed; {@code false} if it
   *         has already been seen inside the retention window
   */
  boolean claim(UUID entity, String code);

  /**
   * A guard that claims nothing and permits everything.
   *
   * <p>The opt-out for a caller that has its own replay protection, or that has weighed
   * the risk and decided a ninety-second replay window is acceptable. It is not the
   * default, because a library that silently permits one-time passwords to be reused is
   * a finding waiting to be written up.</p>
   */
  TOTPReplayGuard PERMISSIVE = (entity, code) -> true;

  /**
   * The default: a bounded, time-limited record held in this process only.
   *
   * <p><b>Per-process.</b> A deployment running more than one instance gets protection
   * only against replays that happen to land on the same instance, which is not
   * protection. Such a deployment should supply its own shared implementation via
   * {@link Credentialed#setTOTPReplayGuard(TOTPReplayGuard)} -- backed by the database or
   * whatever else every instance can see.</p>
   *
   * <p>Bounded on purpose. An unbounded map keyed partly on caller-supplied input is a
   * memory-exhaustion lever; entries are evicted oldest-first past the cap and lazily
   * once they age out, so the worst an attacker achieves by flooding it is to evict
   * their own earlier attempts.</p>
   */
  final class InMemory implements TOTPReplayGuard {

    /** Comfortably past the verifier's own tolerance of one time step either side. */
    private static final long DEFAULT_TTL_MILLIS = 120_000L;

    /** Roughly a megabyte of keys in the worst case. */
    private static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final long ttlMillis;
    private final Map<String, Long> spent;

    /** Instantiates a guard with the default retention and capacity. */
    public InMemory() {
      this(DEFAULT_TTL_MILLIS, DEFAULT_MAX_ENTRIES);
    }

    /**
     * Instantiates a guard.
     *
     * @param ttlMillis how long a claimed code is remembered; must exceed the verifier's
     *        allowed discrepancy or a code can outlive its own record and be replayed
     * @param maxEntries the most codes to remember at once
     */
    public InMemory(long ttlMillis, int maxEntries) {
      this.ttlMillis = ttlMillis;
      this.spent = new LinkedHashMap<>(16, 0.75f, false) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
          return size() > maxEntries;
        }
      };
    }

    @Override public boolean claim(UUID entity, String code) {
      Objects.requireNonNull(entity);
      Objects.requireNonNull(code);

      // Written as an escape. A literal NUL here makes the whole file binary to git and
      // invisible to grep -- which is exactly how the separator in an unrelated cache key
      // elsewhere in this codebase escaped notice. NUL rather than a printable separator
      // because claim() is public API and cannot assume the code has been validated.
      final String key = entity + "\0" + code;
      final long now = System.currentTimeMillis();

      synchronized(spent) {
        Long seenAt = spent.get(key);
        if(null != seenAt && now - seenAt < ttlMillis) return false;

        // Insertion-ordered, so the oldest entries are at the head and the first one still
        // inside the window ends the sweep. Amortised constant per claim.
        var iterator = spent.entrySet().iterator();
        while(iterator.hasNext()) {
          if(now - iterator.next().getValue() < ttlMillis) break;
          iterator.remove();
        }

        spent.remove(key);
        spent.put(key, now);
        return true;
      }
    }
  }

}
