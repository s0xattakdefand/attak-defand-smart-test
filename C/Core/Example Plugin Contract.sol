// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICoreController {
    function executeFromPlugin(bytes32 name) external;
}

contract SamplePlugin {
    ICoreController public core;
    bytes32 public pluginName;

    event ActionPerformed(address user);

    constructor(address _core, bytes32 _name) {
        core = ICoreController(_core);
        pluginName = _name;
    }

    function performSecureAction() external {
        core.executeFromPlugin(pluginName);
        emit ActionPerformed(msg.sender);
    }
}
