// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApprovedEntropySource {
    address public admin;
    mapping(address => bool) public approvedSources;
    mapping(bytes32 => bool) public usedEntropy;

    event EntropyRegistered(address indexed source, bytes32 appId, bytes32 entropyHash);
    event EntropyRejected(address indexed caller, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function approveSource(address source) external onlyAdmin {
        approvedSources[source] = true;
    }

    function revokeSource(address source) external onlyAdmin {
        approvedSources[source] = false;
    }

    function submitEntropy(
        bytes32 appId,
        bytes32 entropyHash,
        uint256 nonce,
        address user
    ) external {
        require(approvedSources[msg.sender], "Entropy source not approved");

        bytes32 combined = keccak256(abi.encodePacked(appId, user, nonce));
        require(entropyHash == combined, "Entropy hash mismatch");

        require(!usedEntropy[entropyHash], "Entropy already used");
        usedEntropy[entropyHash] = true;

        emit EntropyRegistered(msg.sender, appId, entropyHash);
    }

    function isEntropyUsed(bytes32 entropyHash) external view returns (bool) {
        return usedEntropy[entropyHash];
    }
}
