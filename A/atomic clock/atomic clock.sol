// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AtomicTimeVerifier - Verifies time-stamped data using atomic-clock-bound attestations

contract AtomicTimeVerifier {
    address public trustedSigner;      // Oracle or bridge attester
    uint256 public constant MAX_DRIFT = 10 minutes;

    struct TimeStampProof {
        uint256 unixTime;
        bytes32 payloadHash;
        bytes signature;
    }

    event TimeVerified(address indexed verifier, uint256 time, bytes32 payloadHash);

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    function verifyTimestamp(
        uint256 unixTime,
        bytes32 payloadHash,
        bytes calldata signature
    ) external view returns (bool) {
        require(block.timestamp >= unixTime, "Future timestamp");
        require(block.timestamp - unixTime <= MAX_DRIFT, "Stale or drifted");

        bytes32 message = keccak256(abi.encodePacked(unixTime, payloadHash));
        bytes32 ethHash = toEthSignedMessageHash(message);
        address recovered = recover(ethHash, signature);
        require(recovered == trustedSigner, "Invalid signer");

        return true;
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
