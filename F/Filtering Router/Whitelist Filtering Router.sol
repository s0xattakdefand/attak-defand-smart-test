// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FilteringRouter
 * @notice Only routes to approved destination contracts.
 */
contract FilteringRouter {
    mapping(address => bool) public approvedTargets;
    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function approveTarget(address target, bool approved) external onlyAdmin {
        approvedTargets[target] = approved;
    }

    function route(address target, bytes calldata data) external returns (bytes memory) {
        require(approvedTargets[target], "Target not approved");
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }
}
