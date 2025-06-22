// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfigurationPayloadValidator {
    address public admin;
    mapping(bytes32 => bool) public usedPayloads;
    mapping(bytes4 => bool) public allowedSelectors;

    event PayloadExecuted(address executor, bytes4 selector, bytes32 payloadHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
        allowedSelectors[bytes4(keccak256("updateFee(uint256)"))] = true;
        allowedSelectors[bytes4(keccak256("setOracle(address)"))] = true;
    }

    function executePayload(bytes calldata payload) external onlyAdmin {
        bytes4 selector = bytes4(payload[:4]);
        require(allowedSelectors[selector], "Selector not allowed");

        bytes32 payloadHash = keccak256(payload);
        require(!usedPayloads[payloadHash], "Payload already used");
        usedPayloads[payloadHash] = true;

        (bool ok, ) = address(this).call(payload);
        require(ok, "Payload execution failed");

        emit PayloadExecuted(msg.sender, selector, payloadHash);
    }

    // Example configuration functions
    uint256 public fee;
    address public oracle;

    function updateFee(uint256 newFee) external onlyAdmin {
        fee = newFee;
    }

    function setOracle(address newOracle) external onlyAdmin {
        oracle = newOracle;
    }
}
