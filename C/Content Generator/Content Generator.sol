// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ContentHashRegistry {
    address public admin;

    mapping(bytes32 => bool) public approvedContent;
    mapping(bytes32 => bool) public usedNonces;

    event ContentApproved(bytes32 hash, string description);
    event ContentRejected(bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function approveContent(bytes calldata content, string calldata description, bytes32 nonce) external onlyAdmin {
        require(!usedNonces[nonce], "Nonce already used");
        bytes32 hash = keccak256(content);
        approvedContent[hash] = true;
        usedNonces[nonce] = true;
        emit ContentApproved(hash, description);
    }

    function isApproved(bytes calldata content) external view returns (bool) {
        return approvedContent[keccak256(content)];
    }
}
