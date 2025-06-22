// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UpgradeFreezeGuard {
    uint256 public immutable deploymentBlock;
    uint256 public freezePeriod; // in blocks

    address public admin;

    constructor(uint256 _freezePeriod) {
        deploymentBlock = block.number;
        freezePeriod = _freezePeriod;
        admin = msg.sender;
    }

    modifier afterFreeze() {
        require(block.number >= deploymentBlock + freezePeriod, "Upgrade locked");
        _;
    }

    function upgradeLogic() external afterFreeze onlyAdmin {
        // Protected upgrade logic goes here
    }

    function setFreezePeriod(uint256 newFreezePeriod) external onlyAdmin {
        freezePeriod = newFreezePeriod;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }
}
