// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Omitted AAD Attack, Modified AAD Replay Attack, Domain Drift Attack
/// Defense Types: Bind AAD to Signature/Proof, Strict AAD Validation, Domain Separation

contract AdditionalAuthenticationDataSystem {
    address public verifier;

    event AuthenticatedActionPerformed(address indexed user, string action);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        verifier = msg.sender; // deployer is verifier for simulation
    }

    /// ATTACK Simulation: Omit AAD when signing
    function attackOmitAAD(string calldata action) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(action)); // wrong: AAD missing
    }

    /// DEFENSE: Proper secure hash binding main action + AAD
    function hashWithAAD(string calldata action, string calldata aad) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(action, aad));
    }

    /// DEFENSE: Verify signed action + AAD
    function verifyActionWithAAD(
        string calldata action,
        string calldata aad,
        bytes32 providedHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 expectedHash = keccak256(abi.encodePacked(action, aad));
        require(providedHash == expectedHash, "Hash mismatch - possible AAD omission");

        address signer = ecrecover(toEthSignedMessageHash(expectedHash), v, r, s);
        if (signer != verifier) {
            emit AttackDetected(msg.sender, "Invalid signature or AAD mismatch");
            revert("Unauthorized");
        }

        emit AuthenticatedActionPerformed(msg.sender, action);
    }

    /// Helper: standard Ethereum signed message prefix
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
