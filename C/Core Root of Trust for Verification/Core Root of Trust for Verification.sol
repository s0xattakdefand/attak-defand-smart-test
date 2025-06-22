// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CoreRootOfTrustForVerification {
    address public immutable admin;
    mapping(bytes32 => bool) public trustedHashes;
    mapping(address => bool) public trustedVerifiers;

    event VerifierTrusted(address verifier);
    event HashTrusted(bytes32 indexed hash);
    event VerificationPassed(address user, bytes32 hash, string context);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Admin registers a trusted verifier contract (e.g., zkVerifier or signature module)
    function trustVerifier(address verifier) external onlyAdmin {
        require(verifier != address(0), "Invalid verifier");
        trustedVerifiers[verifier] = true;
        emit VerifierTrusted(verifier);
    }

    // Admin registers a trusted hash (e.g., logic bytecode, config)
    function trustHash(bytes32 hash) external onlyAdmin {
        trustedHashes[hash] = true;
        emit HashTrusted(hash);
    }

    // Public verification hook
    function verify(bytes32 hash, string calldata context) external returns (bool) {
        require(trustedHashes[hash], "Hash not trusted");
        emit VerificationPassed(msg.sender, hash, context);
        return true;
    }

    // View only
    function isTrusted(bytes32 hash) external view returns (bool) {
        return trustedHashes[hash];
    }
}
