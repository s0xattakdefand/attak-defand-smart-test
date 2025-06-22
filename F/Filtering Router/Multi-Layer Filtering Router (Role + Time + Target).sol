// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract LayeredFilteringRouter is AccessControl {
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    mapping(address => bool) public approvedTargets;
    mapping(bytes4 => bool) public allowedFunctions;
    uint256 public routerStartBlock;
    uint256 public routerEndBlock;

    constructor(address admin, uint256 start, uint256 end) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTER_ROLE, admin);
        routerStartBlock = start;
        routerEndBlock = end;
    }

    function approveTarget(address target, bool approved) external onlyRole(DEFAULT_ADMIN_ROLE) {
        approvedTargets[target] = approved;
    }

    function allowFunction(bytes4 selector, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        allowedFunctions[selector] = allowed;
    }

    function route(address target, bytes calldata data) external onlyRole(ROUTER_ROLE) returns (bytes memory) {
        require(block.number >= routerStartBlock && block.number <= routerEndBlock, "Time filter failed");
        require(approvedTargets[target], "Target not approved");
        bytes4 sig;
        assembly {
            sig := calldataload(data.offset)
        }
        require(allowedFunctions[sig], "Function not allowed");

        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }
}
