/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc;

import org.apache.tuweni.bytes.Bytes;

/** The interface for PQ Signature algorithms. NB : only handles verification */
public interface SignatureAlgorithmPQC {

  /** Identifier (1st byte of payload) */
  byte algorithmId();

  /** Algorithm name */
  String name();

  /** Public key length (in bytes) */
  int publicKeyLength();

  /** Signature length (in bytes) or max length if variable (Falcon case) */
  int signatureLength();

  /**
   * Check if signature length is valid. Default implementation checks exact length.
   *
   * @param length the length
   * @return true if valid
   */
  default boolean isSignatureLengthValid(final int length) {
    return length == signatureLength();
  }

  /**
   * Create PQ public key.
   *
   * @param encoded the encoded
   * @return the PQ public key
   */
  PQCPublicKey createPublicKey(Bytes encoded);

  /**
   * Create PQ signature.
   *
   * @param encoded the encoded
   * @return the PQ signature
   */
  PQCSignature createSignature(Bytes encoded);

  /**
   * Verify given message digest data, signature and public key.
   *
   * @param data the data
   * @param signature the signature
   * @param pub the pub
   * @return the boolean
   */
  boolean verify(Bytes data, PQCSignature signature, PQCPublicKey pub);
}
