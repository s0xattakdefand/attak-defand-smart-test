// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract zkKYCLaunchpad {
    mapping(bytes32 => bool) public kycIdentities;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function whitelist(bytes32 zkHash) external {
        require(msg.sender == admin, "Only admin");
        kycIdentities[zkHash] = true;
    }

    function participate(bytes32 zkHash) external payable {
        require(kycIdentities[zkHash], "Not KYC verified");
        require(msg.value == 1 ether, "Must pay to enter");
        // Accept entry
    }

    receive() external payable {}
}
