// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArtifactRegistry - Tracks verified artifacts of deployed contracts

contract ArtifactRegistry {
    address public admin;

    struct Artifact {
        address deployedAddress;
        bytes32 sourceHash;     // keccak256(source code)
        bytes32 bytecodeHash;   // keccak256(bytecode)
        bytes32 abiHash;        // keccak256(ABI json string)
        string compilerVersion;
        uint256 timestamp;
    }

    bytes32[] public artifactIds;
    mapping(bytes32 => Artifact) public artifacts;

    event ArtifactRegistered(bytes32 indexed id, address indexed deployedAddress);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerArtifact(
        address deployedAddress,
        bytes32 sourceHash,
        bytes32 bytecodeHash,
        bytes32 abiHash,
        string calldata compilerVersion
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(deployedAddress, sourceHash, bytecodeHash, abiHash));
        artifacts[id] = Artifact({
            deployedAddress: deployedAddress,
            sourceHash: sourceHash,
            bytecodeHash: bytecodeHash,
            abiHash: abiHash,
            compilerVersion: compilerVersion,
            timestamp: block.timestamp
        });
        artifactIds.push(id);
        emit ArtifactRegistered(id, deployedAddress);
    }

    function getAllArtifacts() external view returns (bytes32[] memory) {
        return artifactIds;
    }

    function getArtifact(bytes32 id) external view returns (Artifact memory) {
        return artifacts[id];
    }
}
