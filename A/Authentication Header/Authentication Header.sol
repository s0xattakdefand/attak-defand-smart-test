// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AuthHeaderVerifier — Verifies authentication headers attached to payloads
contract AuthHeaderVerifier {
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("zkDAO-v1");

    event AuthHeaderVerified(address signer, uint256 nonce, bytes32 payloadHash);

    mapping(address => uint256) public lastNonce;

    struct AuthHeader {
        address from;
        uint256 nonce;
        uint256 expires;
        bytes32 payloadHash;
    }

    function verifyHeader(
        AuthHeader calldata header,
        bytes calldata signature
    ) external {
        require(block.timestamp <= header.expires, "Expired header");
        require(header.nonce > lastNonce[header.from], "Nonce replay");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(
                    header.from,
                    header.nonce,
                    header.expires,
                    header.payloadHash
                ))
            )
        );

        address signer = recoverSigner(digest, signature);
        require(signer == header.from, "Signature mismatch");

        lastNonce[signer] = header.nonce;
        emit AuthHeaderVerified(signer, header.nonce, header.payloadHash);
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        return ecrecover(hash, v, r, s);
    }
}
