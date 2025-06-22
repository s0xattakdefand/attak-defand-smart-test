// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract VaultV2 {
    address public immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    function withdraw() external {
        require(tx.origin == deployer, "Use EOA only");
        payable(deployer).transfer(address(this).balance);
    }

    receive() external payable {}
}
