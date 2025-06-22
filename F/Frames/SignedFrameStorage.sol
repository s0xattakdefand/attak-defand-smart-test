// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignedFrameStorage {
    using ECDSA for bytes32;

    struct Frame {
        uint256 timestamp;
        string payload;
        bytes signature;
    }

    mapping(address => bool) public processed;
    mapping(address => string) public storedPayloads;

    function submit(Frame calldata frame) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, frame.payload, frame.timestamp));
        address signer = hash.toEthSignedMessageHash().recover(frame.signature);

        require(signer == msg.sender, "Invalid signer");
        require(!processed[signer], "Replay detected");

        processed[signer] = true;
        storedPayloads[signer] = frame.payload;
    }
}
