// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract VaultTemplate {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not authorized");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

contract CloneVaultFactory {
    address[] public vaults;

    function deployVault() external returns (address newVault) {
        newVault = address(new VaultTemplate());
        vaults.push(newVault);
    }

    function getVaults() external view returns (address[] memory) {
        return vaults;
    }
}
