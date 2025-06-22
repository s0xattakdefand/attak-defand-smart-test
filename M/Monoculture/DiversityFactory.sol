// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract VaultV1 {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); payable(owner).transfer(address(this).balance); }
    receive() external payable {}
}

contract VaultV2 {
    address public owner;
    constructor() { owner = tx.origin; }
    function withdraw() external { require(tx.origin == owner); payable(owner).transfer(address(this).balance); }
    receive() external payable {}
}

contract DiversityFactory {
    address[] public deployedVaults;

    function deployVault() external returns (address vault) {
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2;

        if (rand == 0) {
            vault = address(new VaultV1());
        } else {
            vault = address(new VaultV2());
        }

        deployedVaults.push(vault);
    }

    function getVaults() external view returns (address[] memory) {
        return deployedVaults;
    }
}
