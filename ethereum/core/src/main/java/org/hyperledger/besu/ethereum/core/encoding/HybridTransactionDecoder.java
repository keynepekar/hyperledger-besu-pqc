/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.ethereum.core.encoding;

import static org.hyperledger.besu.ethereum.core.encoding.AccessListTransactionDecoder.readAccessList;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;

public class HybridTransactionDecoder {

    public static Transaction decode(final Bytes input) {
        // Decoding Logic
        final RLPInput rlpInput = new org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput(input, false);
        rlpInput.enterList();
        final BigInteger chainId = rlpInput.readBigIntegerScalar();
        final long nonce = rlpInput.readLongScalar();
        final Wei maxPriorityFeePerGas = Wei.of(rlpInput.readUInt256Scalar());
        final Wei maxFeePerGas = Wei.of(rlpInput.readUInt256Scalar());
        final long gasLimit = rlpInput.readLongScalar();
        final Bytes toBytes = rlpInput.readBytes();
        final Wei value = Wei.of(rlpInput.readUInt256Scalar());
        final Bytes payload = rlpInput.readBytes();
        final var accessList = readAccessList(rlpInput);

        final byte pqcAlgorithmId = rlpInput.readByte();
        final Bytes pqcPublicKey = rlpInput.readBytes();

        // Read ECDSA Signature
        final BigInteger v = rlpInput.readBigIntegerScalar();
        final BigInteger r = rlpInput.readBigIntegerScalar();
        final BigInteger s = rlpInput.readBigIntegerScalar();
        final SECPSignature signature = SignatureAlgorithmFactory.getInstance().createSignature(r, s,
                v.byteValueExact());

        final Bytes pqcSignature = rlpInput.readBytes();

        rlpInput.leaveList();

        return Transaction.builder()
                .type(TransactionType.HYBRID)
                .chainId(chainId)
                .nonce(nonce)
                .maxPriorityFeePerGas(maxPriorityFeePerGas)
                .maxFeePerGas(maxFeePerGas)
                .gasLimit(gasLimit)
                .to(toBytes.isEmpty() ? null : Address.wrap(toBytes))
                .value(value)
                .payload(payload)
                .accessList(accessList)
                .pqcAlgorithmId(pqcAlgorithmId)
                .pqcPublicKey(pqcPublicKey)
                .signature(signature)
                .pqcSignature(pqcSignature)
                .build();
    }
}
