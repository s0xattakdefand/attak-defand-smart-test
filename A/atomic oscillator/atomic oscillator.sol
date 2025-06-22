// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AtomicOscillatorVerifier - Verifies trusted timestamps signed by an atomic oscillator

contract AtomicOscillatorVerifier {
    address public trustedOscillator;
    uint256 public constant MAX_DRIFT = 5 minutes;

    event TimestampVerified(address indexed source, uint256 oscillatorTime, bytes32 payloadHash);

    constructor(address _trustedOscillator) {
        trustedOscillator = _trustedOscillator;
    }

    function verifyTimestampedPayload(
        uint256 oscillatorTime,
        bytes32 payloadHash,
        bytes calldata signature
    ) external view returns (bool) {
        require(block.timestamp >= oscillatorTime, "Timestamp in future");
        require(block.timestamp - oscillatorTime <= MAX_DRIFT, "Oscillator drift too large");

        bytes32 msgHash = keccak256(abi.encodePacked(oscillatorTime, payloadHash));
        bytes32 ethSigned = getEthSignedMessageHash(msgHash);
        address recovered = recover(ethSigned, signature);

        require(recovered == trustedOscillator, "Invalid oscillator signature");

        return true;
    }

    function getEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
