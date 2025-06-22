// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BootableSystem is Initializable, Ownable {
    string public systemName;
    bool public isBooted;

    event SystemBooted(address bootloader, string name, uint256 timestamp);

    /// ✅ Constructor-style: hardcoded for single-deploy systems
    constructor() {
        systemName = "StaticBoot";
        isBooted = true;
        emit SystemBooted(msg.sender, systemName, block.timestamp);
    }

    /// ✅ Upgradeable-style initializer for proxies
    function initialize(string calldata _name, address _admin) public initializer {
        systemName = _name;
        isBooted = true;
        _transferOwnership(_admin);
        emit SystemBooted(_admin, _name, block.timestamp);
    }

    function bootCheck() external view returns (bool booted, string memory name) {
        return (isBooted, systemName);
    }
}
