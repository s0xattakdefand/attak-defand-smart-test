// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecurityOfficial {
    address public immutable deployer;
    address public official;
    bool public paused;

    event OfficialChanged(address indexed newOfficial);
    event EmergencyPaused(address indexed by);
    event EmergencyActionExecuted(bytes4 indexed selector, address target);

    modifier onlyOfficial() {
        require(msg.sender == official, "Not security official");
        _;
    }

    constructor(address initialOfficial) {
        deployer = msg.sender;
        official = initialOfficial;
    }

    function changeOfficial(address newOfficial) external {
        require(msg.sender == deployer || msg.sender == official, "Not authorized");
        official = newOfficial;
        emit OfficialChanged(newOfficial);
    }

    function pauseProtocol() external onlyOfficial {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    function executeEmergency(address target, bytes calldata data) external onlyOfficial {
        require(paused, "Not in emergency state");
        (bool success, ) = target.call(data);
        require(success, "Emergency call failed");

        emit EmergencyActionExecuted(bytes4(data[:4]), target);
    }
}
