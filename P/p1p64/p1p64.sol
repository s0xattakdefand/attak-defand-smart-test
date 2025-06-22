// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title P1toP64BitfieldAttackDefense - Attack and Defense Simulation for Bitfield Handling (P1 ... P64) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Bitfield Handling (No Length Checking, Vulnerable to Drift and Overflows)
contract InsecureBitfield {
    mapping(address => uint64) public permissions; // Only intended for 64 bits, but unchecked input

    event PermissionsSet(address indexed user, uint64 permissions);

    function setPermissions(uint64 rawBits) external {
        // 🔥 No bitmasking, no drift protection
        permissions[msg.sender] = rawBits;
        emit PermissionsSet(msg.sender, rawBits);
    }
}

/// @notice Secure Bitfield Handling with Full Masking, Verification, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureBitfield is Ownable {
    using ECDSA for bytes32;

    mapping(address => uint64) private permissions;
    mapping(bytes32 => bool) public usedUpdates;

    uint64 public constant BIT_MASK = 0xFFFFFFFFFFFFFFFF; // 64 bits

    event PermissionsSet(address indexed user, uint64 sanitizedPermissions, bytes32 updateHash);

    function setPermissions(uint64 proposedBits, uint256 nonce, bytes calldata signature) external {
        require((proposedBits & ~BIT_MASK) == 0, "Invalid bitfield length");

        bytes32 updateHash = keccak256(abi.encodePacked(msg.sender, proposedBits, nonce, address(this), block.chainid));
        require(!usedUpdates[updateHash], "Replay detected");

        address signer = updateHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        usedUpdates[updateHash] = true;

        permissions[msg.sender] = proposedBits & BIT_MASK;
        emit PermissionsSet(msg.sender, proposedBits & BIT_MASK, updateHash);
    }

    function getPermissions(address user) external view returns (uint64) {
        return permissions[user];
    }
}

/// @notice Attack contract simulating overflow and drift manipulation
contract BitfieldIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectOversizedPermissions(uint256 forgedBits) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("setPermissions(uint64)", uint64(forgedBits))
        );
    }
}
