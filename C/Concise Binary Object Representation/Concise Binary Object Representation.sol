// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@chainlink/contracts/src/v0.8/vendor/CBORChainlink.sol";
import "@chainlink/contracts/src/v0.8/Chainlink.sol";

/// @title CBORPayloadEmitter — Encodes structured data in CBOR format using Chainlink lib
contract CBORPayloadEmitter {
    using CBORChainlink for BufferChainlink.buffer;

    BufferChainlink.buffer private buf;

    event EncodedCBOR(bytes payload);
    event DecodedValue(string key, uint256 numberValue);

    constructor() {
        buf.init(256);
    }

    /// ✅ Emit a CBOR-encoded payload
    function emitPayload(string calldata id, uint256 value, address user) external {
        buf.init(256);
        buf.encodeString("requestId");
        buf.encodeString(id);

        buf.encodeString("value");
        buf.encodeUInt(value);

        buf.encodeString("user");
        buf.encodeAddress(user);

        emit EncodedCBOR(buf.buf);
    }

    /// ❌ Decoding must be done off-chain or via trusted bridge parser
}
