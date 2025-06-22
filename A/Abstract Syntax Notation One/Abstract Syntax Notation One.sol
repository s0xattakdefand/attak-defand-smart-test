// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ASN1Decoder - Simulated ASN.1-style TLV parsing for Web3 contract interoperability

contract ASN1Decoder {
    struct ASN1Field {
        uint8 tag;
        uint length;
        bytes value;
    }

    /// @notice Parses a single ASN.1-style TLV field from calldata
    function decodeASN1(bytes calldata data, uint offset) external pure returns (ASN1Field memory field, uint nextOffset) {
        require(data.length > offset + 2, "Truncated");

        uint8 tag = uint8(data[offset]);
        uint8 length = uint8(data[offset + 1]);
        require(data.length >= offset + 2 + length, "Invalid length");

        bytes memory val = data[offset + 2 : offset + 2 + length];
        field = ASN1Field(tag, length, val);
        nextOffset = offset + 2 + length;
    }

    /// @notice Parses multiple fields (SEQUENCE)
    function decodeSequence(bytes calldata data) external pure returns (ASN1Field[] memory fields) {
        uint offset = 0;
        ASN1Field ; // Max 10 fields for demo
        uint count = 0;

        while (offset < data.length && count < 10) {
            (ASN1Field memory f, uint next) = ASN1Decoder.decodeASN1(data, offset);
            temp[count++] = f;
            offset = next;
        }

        ASN1Field[] memory out = new ASN1Field[](count);
        for (uint i = 0; i < count; i++) {
            out[i] = temp[i];
        }
        return out;
    }
}
