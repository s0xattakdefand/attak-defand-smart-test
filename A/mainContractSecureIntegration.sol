// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISecureAccessControlService {
    function isAuthorized(address user) external view returns (bool);
}

contract MainContractSecure {
    ISecureAccessControlService public aclService;

    constructor(address aclServiceAddress) {
        aclService = ISecureAccessControlService(aclServiceAddress);
    }

    modifier onlyAuthorized() {
        require(aclService.isAuthorized(msg.sender), "Unauthorized access");
        _;
    }

    function sensitiveOperation() public view onlyAuthorized returns (string memory) {
        return "Securely accessed sensitive data!";
    }
}
