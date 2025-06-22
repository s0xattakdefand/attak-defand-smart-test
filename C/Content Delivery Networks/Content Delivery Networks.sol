// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CDNContentHashRegistry {
    address public admin;
    mapping(bytes32 => bool) public validContentHashes;
    mapping(bytes32 => string) public cidToDescription;

    event ContentRegistered(bytes32 hash, string cid, string description);
    event ContentVerified(bytes32 hash, address verifier);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerContent(bytes32 hash, string calldata cid, string calldata description) external onlyAdmin {
        validContentHashes[hash] = true;
        cidToDescription[hash] = description;
        emit ContentRegistered(hash, cid, description);
    }

    function verifyContent(bytes calldata content) external returns (bool) {
        bytes32 hash = keccak256(content);
        if (validContentHashes[hash]) {
            emit ContentVerified(hash, msg.sender);
            return true;
        }
        return false;
    }
}
