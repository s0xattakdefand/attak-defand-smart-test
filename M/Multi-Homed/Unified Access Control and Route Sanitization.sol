// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract UnifiedAccessProxy {
    address public admin;
    mapping(address => bool) public approvedBackends;

    constructor(address[] memory initialBackends) {
        admin = msg.sender;
        for (uint256 i = 0; i < initialBackends.length; i++) {
            approvedBackends[initialBackends[i]] = true;
        }
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    function route(address target, bytes calldata data) external onlyAdmin {
        require(approvedBackends[target], "Untrusted backend");
        (bool ok, ) = target.call(data);
        require(ok, "Call failed");
    }

    function approveBackend(address target, bool status) external onlyAdmin {
        approvedBackends[target] = status;
    }
}
