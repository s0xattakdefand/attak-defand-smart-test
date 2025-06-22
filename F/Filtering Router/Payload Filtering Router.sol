// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PayloadFilterRouter
 * @notice Filters both destination and function selector (e.g., only allows "transfer(address,uint256)").
 */
contract PayloadFilterRouter {
    mapping(address => bool) public approvedTargets;
    mapping(bytes4 => bool) public allowedFunctions;
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

    function allowFunction(bytes4 selector, bool allowed) external onlyAdmin {
        allowedFunctions[selector] = allowed;
    }

    function route(address target, bytes calldata data) external returns (bytes memory) {
        require(approvedTargets[target], "Disallowed target");
        bytes4 sig;
        assembly {
            sig := calldataload(data.offset)
        }
        require(allowedFunctions[sig], "Disallowed function");
        (bool success, bytes memory result) = target.call(data);
        require(success, "Failed call");
        return result;
    }
}
