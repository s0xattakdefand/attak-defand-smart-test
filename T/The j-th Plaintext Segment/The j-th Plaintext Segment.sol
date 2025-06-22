// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title JthPlaintextSegmentAttackDefense - Attack and Defense Simulation for Plaintext Segment Handling in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Plaintext Segment Handling (No Authentication, No Replay Protection)
contract InsecurePlaintextSegments {
    mapping(uint256 => bytes) public segments;
    uint256 public segmentCount;

    event SegmentStored(uint256 indexed index, bytes segment);

    function storeSegment(uint256 index, bytes calldata segment) external {
        segments[index] = segment;
        emit SegmentStored(index, segment);
    }

    function reconstructMessage() external view returns (bytes memory fullMessage) {
        for (uint256 i = 0; i < segmentCount; i++) {
            fullMessage = bytes.concat(fullMessage, segments[i]);
        }
    }
}

/// @notice Secure Plaintext Segment Handling (Authenticated, Nonce-Tied, Reassembly Verification)
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecurePlaintextSegments is Ownable {
    using ECDSA for bytes32;

    struct Segment {
        bytes data;
        bool exists;
    }

    mapping(uint256 => Segment) private segments;
    uint256 public expectedSegments;
    uint256 public currentSegments;
    bytes32 public payloadRootHash;
    bool public finalized;

    event SegmentStored(uint256 indexed index);
    event MessageFinalized(bytes32 rootHash);

    constructor(uint256 _expectedSegments) {
        require(_expectedSegments > 0, "Must expect at least one segment");
        expectedSegments = _expectedSegments;
    }

    function storeSegment(uint256 index, bytes calldata segment, bytes calldata signature) external {
        require(!segments[index].exists, "Segment already stored");
        require(!finalized, "Message already finalized");

        bytes32 segmentHash = keccak256(abi.encodePacked(index, segment, address(this), block.chainid));
        address signer = segmentHash.toEthSignedMessageHash().recover(signature);

        require(signer == owner(), "Invalid segment signature");

        segments[index] = Segment({data: segment, exists: true});
        currentSegments++;

        emit SegmentStored(index);

        if (currentSegments == expectedSegments) {
            finalizeMessage();
        }
    }

    function finalizeMessage() internal {
        bytes32 root = keccak256(abi.encodePacked(address(this), block.chainid));
        for (uint256 i = 0; i < expectedSegments; i++) {
            require(segments[i].exists, "Missing segment");
            root = keccak256(abi.encodePacked(root, segments[i].data));
        }
        payloadRootHash = root;
        finalized = true;
        emit MessageFinalized(root);
    }

    function getSegment(uint256 index) external view returns (bytes memory) {
        require(segments[index].exists, "Segment does not exist");
        return segments[index].data;
    }
}

/// @notice Attack contract simulating replay and segment drift
contract SegmentIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectSegment(uint256 index, bytes calldata forgedSegment) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("storeSegment(uint256,bytes)", index, forgedSegment)
        );
    }
}
