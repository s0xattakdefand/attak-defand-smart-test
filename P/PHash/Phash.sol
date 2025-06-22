// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PHashAttackDefense - Attack and Defense Simulation for P Hash Derivation in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure P Hash (Weak Seed, No Nonce Binding)
contract InsecurePHash {
    function deriveKey(bytes32 secret, bytes32 seed) external pure returns (bytes32) {
        // 🔥 Weak HMAC: simple XOR-based hash simulation (not real cryptography!)
        return secret ^ seed;
    }
}

/// @notice Secure P Hash (HMAC Simulation, Seed Randomness, Nonce Binding)
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecurePHash is Ownable {
    event KeyDerived(address indexed caller, bytes32 derivedKey);

    function deriveSecureKey(bytes32 secret, bytes32 seed, uint256 nonce) external view returns (bytes32) {
        require(nonce > 0, "Nonce must be positive");
        bytes32 input = keccak256(abi.encodePacked(secret, seed, nonce, address(this), block.chainid, block.timestamp));
        return keccak256(abi.encodePacked(input));
    }

    function deriveAndEmitKey(bytes32 secret, bytes32 seed, uint256 nonce) external {
        bytes32 key = deriveSecureKey(secret, seed, nonce);
        emit KeyDerived(msg.sender, key);
    }
}

/// @notice Attack contract trying to predict or replay key derivations
contract PHashIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function predictWeakKey(bytes32 guessedSecret, bytes32 guessedSeed) external view returns (bytes32 derivedKey) {
        (bool success, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("deriveKey(bytes32,bytes32)", guessedSecret, guessedSeed)
        );
        require(success, "Call failed");
        derivedKey = abi.decode(data, (bytes32));
    }
}
