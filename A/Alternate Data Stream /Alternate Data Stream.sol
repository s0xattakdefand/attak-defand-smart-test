// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Alternate Data Stream (ADS) System for Smart Contracts
contract AlternateDataStream {
    address public admin;

    mapping(bytes32 => bytes) public ads;

    event StreamWritten(bytes32 indexed key, bytes value);
    event StreamCleared(bytes32 indexed key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Set ADS for any identifier + tag
    function writeADS(bytes32 streamKey, bytes calldata value) external onlyAdmin {
        ads[streamKey] = value;
        emit StreamWritten(streamKey, value);
    }

    /// Clear ADS
    function clearADS(bytes32 streamKey) external onlyAdmin {
        delete ads[streamKey];
        emit StreamCleared(streamKey);
    }

    /// Generate namespaced key
    function getStreamKey(address base, string memory tag) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(base, tag));
    }

    /// Read stream
    function readADS(bytes32 streamKey) external view returns (bytes memory) {
        return ads[streamKey];
    }
}
