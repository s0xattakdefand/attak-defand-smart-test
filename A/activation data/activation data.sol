// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Replay, Fake Data, Drift
/// Defense Types: Signature Check, Nonce, Event Logs

contract ActivationDataManager {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedActivations;

    event Activated(address indexed user, string purpose, bytes32 activationId);
    event AttackDetected(address indexed attacker, string reason);

    /// Use activation data (signed input)
    function activate(string calldata purpose, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[msg.sender], "Nonce mismatch");

        bytes32 payloadHash = keccak256(abi.encodePacked(msg.sender, purpose, nonce));
        bytes32 ethSigned = ECDSA.toEthSignedMessageHash(payloadHash);
        address signer = ECDSA.recover(ethSigned, signature);

        require(signer == msg.sender, "Invalid activation signature");
        require(!usedActivations[payloadHash], "Replay detected");

        usedActivations[payloadHash] = true;
        nonces[msg.sender]++;

        emit Activated(msg.sender, purpose, payloadHash);
    }

    /// ATTACK: Fake or reused activation
    function attackFakeActivation(string calldata purpose, uint256 badNonce) external {
        emit AttackDetected(msg.sender, "Fake or replayed activation");
        revert("Blocked attack");
    }

    /// View if used
    function isUsed(bytes32 activationId) external view returns (bool) {
        return usedActivations[activationId];
    }
}

/// Lightweight ECDSA lib
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: invalid signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}
