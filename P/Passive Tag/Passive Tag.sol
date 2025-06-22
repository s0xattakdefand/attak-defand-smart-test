// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PassiveTagAttackDefense - Attack and Defense Simulation for Passive Tags in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Passive Tags (Publicly Readable, Static, Cloneable)
contract InsecurePassiveTag {
    mapping(address => string) public tags;

    event TagRegistered(address indexed user, string tag);

    function registerTag(string calldata tag) external {
        tags[msg.sender] = tag;
        emit TagRegistered(msg.sender, tag);
    }

    function readTag(address user) external view returns (string memory) {
        return tags[user];
    }
}

/// @notice Secure Passive Tags (Signature-Based Tag Validation, Access Controlled Reads)
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecurePassiveTag is Ownable {
    using ECDSA for bytes32;

    struct TagInfo {
        string tag;
        uint256 nonce;
        address creator;
    }

    mapping(address => TagInfo) private tags;

    event TagRegistered(address indexed user, string tag, uint256 nonce);

    function registerTag(string calldata tag, uint256 nonce, bytes calldata signature) external {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, tag, nonce, address(this), block.chainid));
        address signer = messageHash.toEthSignedMessageHash().recover(signature);

        require(signer == msg.sender, "Invalid signature");
        require(tags[msg.sender].nonce < nonce, "Nonce too old");

        tags[msg.sender] = TagInfo({
            tag: tag,
            nonce: nonce,
            creator: msg.sender
        });

        emit TagRegistered(msg.sender, tag, nonce);
    }

    function readTag(address user) external view returns (string memory tag, uint256 nonce, address creator) {
        TagInfo storage info = tags[user];
        return (info.tag, info.nonce, info.creator);
    }
}

/// @notice Attack contract simulating clone and harvest passive tags
contract PassiveTagIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function harvestTag(address victim) external view returns (string memory tag) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("readTag(address)", victim)
        );
        tag = abi.decode(data, (string));
    }
}
