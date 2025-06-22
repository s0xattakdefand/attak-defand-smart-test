// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AspectRouter - Apply reusable behavior (aspects) to modular function calls

contract AspectRouter {
    address public admin;

    mapping(bytes4 => address) public aspectOf; // selector => aspect handler
    mapping(address => bool) public approvedAspects;

    event AspectApplied(bytes4 indexed selector, address aspect);
    event AspectExecuted(address indexed aspect, bytes4 selector);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function approveAspect(address aspect, bool approved) external onlyAdmin {
        approvedAspects[aspect] = approved;
    }

    function assignAspect(bytes4 selector, address aspect) external onlyAdmin {
        require(approvedAspects[aspect], "Aspect not approved");
        aspectOf[selector] = aspect;
        emit AspectApplied(selector, aspect);
    }

    function execute(bytes calldata data) external payable returns (bytes memory result) {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        address aspect = aspectOf[selector];
        require(aspect != address(0), "No aspect assigned");

        (bool success, bytes memory output) = aspect.delegatecall(data);
        require(success, "Aspect call failed");
        emit AspectExecuted(aspect, selector);
        return output;
    }
}
