// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LastBlockPlaintextAttackDefense - Attack and Defense Simulation for Final Partial Block in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Last Block Handling (No Padding Check, Accepts Bad Final Blocks)
contract InsecureLastBlockHandler {
    bytes[] public blocks;
    uint256 public blockSize;

    event BlockStored(uint256 indexed index, bytes data);

    constructor(uint256 _blockSize) {
        require(_blockSize > 0, "Block size must be positive");
        blockSize = _blockSize;
    }

    function storeBlock(bytes calldata data) external {
        // 🔥 No strict check for last block size or padding!
        require(data.length <= blockSize, "Block too big");
        blocks.push(data);
        emit BlockStored(blocks.length - 1, data);
    }

    function reconstructMessage() external view returns (bytes memory message) {
        for (uint256 i = 0; i < blocks.length; i++) {
            message = bytes.concat(message, blocks[i]);
        }
    }
}

/// @notice Secure Last Block Handling (Padding Check, Length Enforcement, Final Signing)
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureLastBlockHandler is Ownable {
    using ECDSA for bytes32;

    bytes[] private blocks;
    uint256 public blockSize;
    bool public finalized;
    bytes32 public finalMessageHash;

    event BlockStored(uint256 indexed index, bytes data);
    event MessageFinalized(bytes32 finalHash);

    constructor(uint256 _blockSize) {
        require(_blockSize > 0, "Block size must be positive");
        blockSize = _blockSize;
    }

    function storeBlock(bytes calldata data, bool isFinal, uint256 nonce, bytes calldata signature) external {
        require(!finalized, "Already finalized");

        if (!isFinal) {
            require(data.length == blockSize, "Intermediate blocks must be full size");
        } else {
            require(data.length > 0 && data.length <= blockSize, "Final block invalid size");
        }

        bytes32 blockHash = keccak256(abi.encodePacked(msg.sender, data, nonce, address(this), block.chainid, isFinal));
        address signer = blockHash.toEthSignedMessageHash().recover(signature);

        require(signer == owner(), "Invalid block signature");

        blocks.push(data);
        emit BlockStored(blocks.length - 1, data);

        if (isFinal) {
            finalizeMessage();
        }
    }

    function finalizeMessage() internal {
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid));
        for (uint256 i = 0; i < blocks.length; i++) {
            hash = keccak256(abi.encodePacked(hash, blocks[i]));
        }
        finalMessageHash = hash;
        finalized = true;
        emit MessageFinalized(hash);
    }

    function getMessageHash() external view returns (bytes32) {
        require(finalized, "Message not finalized yet");
        return finalMessageHash;
    }
}

/// @notice Attack contract trying to store partial and manipulated blocks
contract LastBlockIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectPartialBlock(bytes calldata forgedData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("storeBlock(bytes)", forgedData)
        );
    }
}
