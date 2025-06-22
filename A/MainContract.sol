// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAccessControlService {
    function isAuthorized(address user) external view returns (bool);
}

contract MainContract {
    IAccessControlService public aclService;

    constructor(address aclServiceAddress) {
        aclService = IAccessControlService(aclServiceAddress);
    }

    function sensitiveOperation() public view returns (string memory) {
        require(aclService.isAuthorized(msg.sender), "Not authorized");
        return "Sensitive data exposed!";
    }
}
