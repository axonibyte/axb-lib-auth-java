/*
 * Copyright (c) 2023-2024 Axonibyte Innovations, LLC
 *
 * Licensed under the Blue Oak Model License 1.0.0.
 * See LICENSE for the full terms.
 */
package com.axonibyte.lib.auth;

/**
 * An exception to be thrown if some cryptographic operation failed.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class CryptoException extends Exception {

  /**
   * Instantiates a {@link CryptoException}.
   *
   * @param message details regarding the error
   * @param cause the underlying exception
   */
  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }
  
}
