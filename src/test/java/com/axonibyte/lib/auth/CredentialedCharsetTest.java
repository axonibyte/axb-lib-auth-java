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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.UUID;

import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Pins the byte encoding of everything this class hashes, signs or derives from.
 *
 * <p>Java 18 made UTF-8 the default charset (JEP 400). This library targets 17, where the
 * default still comes from the environment's locale -- so an unqualified
 * {@code String.getBytes()} produces different bytes on two machines that differ only in
 * {@code LANG}, and the resulting failure looks like a wrong password rather than a
 * configuration problem.</p>
 *
 * <p>Two rules govern this file, and both matter:</p>
 *
 * <ol>
 *   <li><b>Only {@code \\uXXXX} escapes, never a literal non-ASCII character.</b> The build
 *       pins {@code -encoding UTF-8} for compilation, but this is the one test whose job is
 *       to be trustworthy even when the encoding setup is broken, and a literal would be
 *       mojibake in the class file before any assertion ran.</li>
 *   <li><b>Frozen values, not round trips</b>, wherever the derivation is under test. A
 *       round trip passes under any charset, because both halves use the same wrong
 *       bytes.</li>
 * </ol>
 *
 * <p>Registered in both {@code cryptoTestSuite.xml} (where it runs under the build's
 * pinned UTF-8) and {@code charsetTestSuite.xml} (where the {@code charsetTest} task runs
 * it under {@code -Dfile.encoding=US-ASCII}). It must pass in both.</p>
 *
 * @author Caleb L. Power &lt;cpower@axonibyte.com&gt;
 */
public class CredentialedCharsetTest {

  /** "caf&eacute; &#26085;&#26412;&#35486;" -- Latin-1 and CJK, so no single-byte charset can carry it. */
  private static final String MESSAGE = "caf\u00e9 \u65e5\u672c\u8a9e";

  private static final String SECRET = "correct horse battery staple";

  @BeforeClass public void assertTheHostileCharsetActuallyLanded() {
    // Without this, a JDK that stops honouring -Dfile.encoding turns the charsetTest task
    // into a silent duplicate of the normal one: green forever, proving nothing. Fail
    // loudly instead of degrading.
    String expected = System.getProperty("axb.test.charset");
    if(null != expected)
      Assert.assertEquals(
          Charset.defaultCharset().name(),
          expected,
          "the charsetTest task did not change the default charset, so it is proving nothing");
  }

  @BeforeMethod public void setUp() {
    Security.addProvider(new BouncyCastleProvider());
    Credentialed.setGlobalSecret(SECRET);
  }

  @Test public void sign_producesASignatureOverUTF8Bytes() throws Exception {
    UUID id = UUID.randomUUID();
    var user = new Credentialed(id, null, null, null);
    user.regenerateKeypair();

    byte[] sig = Base64.decode(user.sign(MESSAGE));

    // Verified independently rather than through verifySig, which would hide the defect:
    // if both sides encode with the same wrong charset they agree with each other and
    // disagree with every other implementation of the scheme.
    var verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(user.getPubkey()));
    byte[] expected = MESSAGE.getBytes(StandardCharsets.UTF_8);
    verifier.update(expected, 0, expected.length);

    Assert.assertTrue(
        verifier.verifySignature(sig),
        "sign() must hash the UTF-8 encoding of the message, whatever the JVM default is");
  }

  @Test public void verifySig_acceptsASignatureOverUTF8Bytes() throws Exception {
    // The direction that matters in practice: the browser signs UTF-8 bytes and the server
    // has to agree. Produced here without going through Credentialed at all.
    var keygen = new Ed25519KeyPairGenerator();
    keygen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
    var keypair = keygen.generateKeyPair();

    var signer = new Ed25519Signer();
    signer.init(true, (Ed25519PrivateKeyParameters)keypair.getPrivate());
    byte[] msg = MESSAGE.getBytes(StandardCharsets.UTF_8);
    signer.update(msg, 0, msg.length);
    String sig = new String(
        Base64.encode(signer.generateSignature()), StandardCharsets.US_ASCII);

    var user = new Credentialed(
        UUID.randomUUID(),
        ((Ed25519PublicKeyParameters)keypair.getPublic()).getEncoded(),
        null,
        null);

    Assert.assertTrue(
        user.verifySig(MESSAGE, sig),
        "a signature over UTF-8 bytes must verify regardless of the JVM default charset");
  }

  @Test public void globalSecret_isDerivedFromUTF8Bytes() throws Exception {
    // A frozen record rather than a round trip. This blob was produced once, under a
    // non-ASCII secret on a UTF-8 JVM; if setGlobalSecret ever derives the current key
    // from anything but UTF-8, the tag check fails and this cannot decrypt.
    final String nonAsciiSecret = "p\u00e4ssw\u00f6rd";
    final UUID id = UUID.fromString("3f2b7c10-9a4d-4e61-8f03-2c5d8e7a1b44");

    Credentialed.setGlobalSecret(nonAsciiSecret);

    var user = new Credentialed(id, null, Base64.decode(FROZEN_UTF8_RECORD), null);
    Assert.assertFalse(
        user.isLegacyFormat(user.getEncPrivkey()),
        "the frozen record is in the current format and must decrypt under the UTF-8 key");
  }

  /**
   * A current-format private key written under the non-ASCII secret above, whose HKDF
   * input was the UTF-8 encoding of that secret. Frozen deliberately: regenerating it is
   * only correct if the on-disk format changes, and only on a JVM whose default charset
   * is already UTF-8.
   */
  private static final String FROZEN_UTF8_RECORD =
      "AS9jBJmdgosBHGd0YPMz0XOAkpSE7bkVD33SDctN6UvVTqFEqsb7LAu25k+kAIT4CZOtaxEp8tzw+SiIAA==";

}
