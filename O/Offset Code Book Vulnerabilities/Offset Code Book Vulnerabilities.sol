// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title OffsetCodeBookAttackDefense - Attack and Defense Simulation for Offset Code Book (OCB) Authenticated Encryption in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure OCB-Like Contract (Weak Nonce and Tag Handling)
contract InsecureOCB {
    struct Message {
        bytes ciphertext;
        bytes32 tag;
        uint256 nonce;
    }

    mapping(bytes32 => bool) public usedNonces;

    event MessageAccepted(address indexed sender, bytes data);

    function submitMessage(Message calldata message) external {
        bytes32 recomputedTag = keccak256(abi.encodePacked(message.ciphertext, message.nonce));
        require(recomputedTag == message.tag, "Tag mismatch");

        require(!usedNonces[keccak256(abi.encodePacked(message.nonce))], "Nonce reused");

        usedNonces[keccak256(abi.encodePacked(message.nonce))] = true;
        emit MessageAccepted(msg.sender, message.ciphertext);
    }
}

/// @notice Secure OCB-Like Contract (Strict Nonce, Tag, and Replay Protection)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureOCB is Ownable {
    struct Message {
        bytes ciphertext;
        bytes32 tag;
        uint256 nonce;
    }

    mapping(bytes32 => bool) private usedNonces;
    mapping(address => uint256) public sessionNonceTracker;

    event MessageAccepted(address indexed sender, bytes data);

    function submitMessageSecure(Message calldata message) external {
        require(message.nonce == sessionNonceTracker[msg.sender], "Invalid session nonce");

        bytes32 recomputedTag = keccak256(abi.encodePacked(
            message.ciphertext,
            message.nonce,
            address(this),
            block.chainid
        ));

        require(recomputedTag == message.tag, "Authentication failed");
        require(!usedNonces[recomputedTag], "Replay detected");

        usedNonces[recomputedTag] = true;
        sessionNonceTracker[msg.sender] += 1;

        emit MessageAccepted(msg.sender, message.ciphertext);
    }
}

/// @notice Attack contract simulating OCB nonce/tag forgery
contract OCBIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeSubmit(bytes calldata fakeCiphertext, uint256 fakeNonce) external returns (bool success) {
        bytes32 fakeTag = keccak256(abi.encodePacked(fakeCiphertext, fakeNonce));

        (success, ) = targetInsecure.call(
            abi.encodeWithSignature(
                "submitMessage((bytes,bytes32,uint256))",
                (fakeCiphertext, fakeTag, fakeNonce)
            )
        );
    }
}
