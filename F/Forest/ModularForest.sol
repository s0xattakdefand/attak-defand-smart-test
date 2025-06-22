// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IForestRoot {
    function isTrustedDomain(address addr) external view returns (bool);
}

contract ModularForestDomain {
    IForestRoot public root;

    constructor(address _root) {
        root = IForestRoot(_root);
    }

    function execute(string memory task) external view returns (string memory) {
        require(root.isTrustedDomain(msg.sender), "Caller not part of forest");
        return string(abi.encodePacked("Executed: ", task));
    }
}
