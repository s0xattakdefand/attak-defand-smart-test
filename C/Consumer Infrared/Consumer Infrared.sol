// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract IRAccessRegistry {
    address public admin;
    mapping(bytes32 => bool) public validIRHashes;
    mapping(bytes32 => bool) public usedHashes;

    event IRAccessGranted(bytes32 hash, address executor);
    event IRAccessRejected(bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerIRHash(bytes32 hash) external onlyAdmin {
        validIRHashes[hash] = true;
    }

    function useIRCode(bytes32 hash) external {
        if (validIRHashes[hash] && !usedHashes[hash]) {
            usedHashes[hash] = true;
            emit IRAccessGranted(hash, msg.sender);
            // perform action (e.g., trigger access)
        } else {
            emit IRAccessRejected(hash);
        }
    }
}
