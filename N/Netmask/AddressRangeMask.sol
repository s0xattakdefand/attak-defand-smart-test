// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AddressRangeMask {
    uint160 public mask;         // Example: 0xFFFFFFFF00000000000000000000000000000000
    uint160 public networkRange; // Base range to compare against

    constructor(uint160 _mask, uint160 _networkRange) {
        mask = _mask;
        networkRange = _networkRange;
    }

    function isInSubnet(address user) public view returns (bool) {
        return (uint160(user) & mask) == networkRange;
    }

    function restrictedAction() external view returns (string memory) {
        require(isInSubnet(msg.sender), "Access denied: Not in netmask range");
        return "Access granted: You're in the network";
    }
}
