// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CASValidator {
    address public admin;
    mapping(bytes32 => bool) public validContentHashes;
    mapping(bytes32 => uint256) public submittedAt;

    event ContentValidated(bytes32 indexed hash, address indexed submitter);
    event ContentRejected(bytes32 indexed hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerValidHash(bytes32 hash) external onlyAdmin {
        validContentHashes[hash] = true;
    }

    function submitContent(bytes calldata data) external {
        bytes32 hash = keccak256(data);
        if (validContentHashes[hash]) {
            submittedAt[hash] = block.timestamp;
            emit ContentValidated(hash, msg.sender);
        } else {
            emit ContentRejected(hash);
        }
    }

    function isValid(bytes calldata data) external view returns (bool) {
        return validContentHashes[keccak256(data)];
    }
}
