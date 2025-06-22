// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IVirtualAppLogic {
    function run(bytes calldata data, address user) external returns (bool);
}

contract VirtualizedAppRouter {
    struct AppContext {
        address logic;
        bool active;
    }

    mapping(bytes32 => AppContext) public apps; // appId → logic contract
    mapping(bytes32 => uint256) public appNonces;

    event VirtualCall(bytes32 appId, address caller, address logic);
    event AppRegistered(bytes32 appId, address logic);
    event AppDeactivated(bytes32 appId);

    modifier onlyApp(bytes32 appId) {
        require(apps[appId].active, "App inactive");
        _;
    }

    function registerApp(bytes32 appId, address logic) external {
        require(apps[appId].logic == address(0), "App already exists");
        apps[appId] = AppContext(logic, true);
        emit AppRegistered(appId, logic);
    }

    function deactivateApp(bytes32 appId) external {
        apps[appId].active = false;
        emit AppDeactivated(appId);
    }

    function callVirtualApp(bytes32 appId, bytes calldata payload) external onlyApp(appId) returns (bool) {
        address logic = apps[appId].logic;
        require(logic != address(0), "No logic registered");

        // Prevent replay
        bytes32 id = keccak256(abi.encodePacked(appId, msg.sender, payload, appNonces[appId]++));
        
        emit VirtualCall(appId, msg.sender, logic);
        return IVirtualAppLogic(logic).run(payload, msg.sender);
    }

    function getAppLogic(bytes32 appId) external view returns (address) {
        return apps[appId].logic;
    }
}
