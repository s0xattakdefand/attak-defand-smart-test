pragma solidity ^0.8.21;

contract TunnelEncryptionValidator {
    bytes32 public expectedHash;

    constructor(bytes32 _expectedHash) {
        expectedHash = _expectedHash;
    }

    function submitDecryption(bytes calldata decryptedPayload) external view returns (bool) {
        return keccak256(decryptedPayload) == expectedHash;
    }
}
