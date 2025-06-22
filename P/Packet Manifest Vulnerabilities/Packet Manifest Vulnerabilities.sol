// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PacketManifestAttackDefense - Attack and Defense Simulation for Packet Manifest Security in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Packet Manifest Handling (No Hash or Replay Protection)
contract InsecurePacketManifest {
    struct Packet {
        address origin;
        address destination;
        bytes payload;
        uint256 timestamp;
    }

    event PacketAccepted(address indexed from, address indexed to, bytes payload);

    function submitPacket(Packet calldata packet) external {
        // 🔥 No hash check, no replay protection!
        require(packet.timestamp <= block.timestamp, "Future packet not allowed");
        emit PacketAccepted(packet.origin, packet.destination, packet.payload);
    }
}

/// @notice Secure Packet Manifest Handling (Hash, Signature, Nonce, and Replay Protection)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePacketManifest is Ownable {
    using ECDSA for bytes32;

    struct PacketManifest {
        address origin;
        address destination;
        bytes payload;
        uint256 timestamp;
        uint256 nonce;
        bytes signature;
    }

    mapping(bytes32 => bool) private processedPackets;
    mapping(address => uint256) public usedNonces;

    event PacketAccepted(address indexed from, address indexed to, bytes payload);

    function submitPacket(PacketManifest calldata manifest) external {
        require(manifest.timestamp <= block.timestamp, "Future timestamp not allowed");
        require(manifest.nonce == usedNonces[manifest.origin], "Invalid nonce");

        bytes32 payloadHash = keccak256(abi.encodePacked(
            manifest.origin,
            manifest.destination,
            manifest.payload,
            manifest.timestamp,
            manifest.nonce,
            address(this),
            block.chainid
        ));

        address signer = payloadHash.toEthSignedMessageHash().recover(manifest.signature);
        require(signer == manifest.origin, "Signature invalid or not from origin");

        require(!processedPackets[payloadHash], "Replay detected");

        processedPackets[payloadHash] = true;
        usedNonces[manifest.origin] += 1;

        emit PacketAccepted(manifest.origin, manifest.destination, manifest.payload);
    }
}

/// @notice Attack contract simulating fake packet manifest submission
contract PacketManifestIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function submitFakePacket(address from, address to, bytes calldata fakePayload) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature(
                "submitPacket((address,address,bytes,uint256))",
                (from, to, fakePayload, block.timestamp)
            )
        );
    }
}
