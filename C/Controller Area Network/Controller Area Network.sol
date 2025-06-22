// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface IController {
    function receiveCANMessage(bytes calldata data) external;
}

contract CANControllerHub is AccessControl {
    bytes32 public constant CONTROLLER_ADMIN = keccak256("CONTROLLER_ADMIN");

    address[] public controllers;
    mapping(address => bool) public isController;

    event ControllerRegistered(address indexed controller);
    event CANMessageBroadcast(address indexed from, bytes payload);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONTROLLER_ADMIN, msg.sender);
    }

    function registerController(address controller) external onlyRole(CONTROLLER_ADMIN) {
        require(!isController[controller], "Already registered");
        controllers.push(controller);
        isController[controller] = true;
        emit ControllerRegistered(controller);
    }

    function broadcast(bytes calldata data) external onlyRole(CONTROLLER_ADMIN) {
        emit CANMessageBroadcast(msg.sender, data);
        for (uint256 i = 0; i < controllers.length; i++) {
            IController(controllers[i]).receiveCANMessage(data);
        }
    }

    function controllerCount() external view returns (uint256) {
        return controllers.length;
    }
}
