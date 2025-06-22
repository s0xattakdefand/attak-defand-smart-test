// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Key Collision Attack, Optional Data Forgery Attack, Weak KDF Attack
/// Defense Types: Mandatory Optional Handling, Explicit Salt Binding, Strong KDF Construction

contract KeyDerivationWithOptionalInput {
    event KeyDerived(address indexed user, bytes32 derivedKey);
    event AttackDetected(string reason);

    mapping(address => bytes32) public userDerivedKeys;

    /// ATTACK Simulation: Derive key ignoring optional data
    function attackWeakKDF(string memory mainInput, string memory salt) external pure returns (bytes32) {
        // Weak: doesn't distinguish absence of optional data
        return keccak256(abi.encodePacked(mainInput, salt));
    }

    /// DEFENSE: Secure KDF with optional X properly normalized
    function deriveSecureKey(
        string memory mainInput,
        string memory salt,
        string memory optionalDataX
    ) external {
        bytes memory normalizedX;
        if (bytes(optionalDataX).length == 0) {
            normalizedX = abi.encodePacked("NULL"); // normalize missing X
        } else {
            normalizedX = abi.encodePacked(optionalDataX);
        }

        bytes32 derivedKey = keccak256(abi.encodePacked(mainInput, salt, normalizedX));

        userDerivedKeys[msg.sender] = derivedKey;
        emit KeyDerived(msg.sender, derivedKey);
    }

    /// Verify if two users have same derived key (possible attack detection)
    function detectCollision(address user1, address user2) external view returns (bool collisionDetected) {
        if (userDerivedKeys[user1] == userDerivedKeys[user2]) {
            collisionDetected = true;
        }
    }

    /// View derived key
    function viewDerivedKey(address user) external view returns (bytes32) {
        return userDerivedKeys[user];
    }
}
