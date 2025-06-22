// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlDesignationRegistry — Assigns roles to addresses for specific control functions
contract ControlDesignationRegistry {
    address public superAdmin;

    // controlKey => designated address
    mapping(bytes32 => address) public designatedController;

    event ControlDesignated(string controlKey, address indexed controller);
    event ControlRevoked(string controlKey, address indexed controller);

    modifier onlySuperAdmin() {
        require(msg.sender == superAdmin, "Not super admin");
        _;
    }

    modifier onlyDesignated(string memory controlKey) {
        require(
            msg.sender == designatedController[keccak256(abi.encodePacked(controlKey))],
            "Not designated controller"
        );
        _;
    }

    constructor() {
        superAdmin = msg.sender;

        // Example designations
        designateControl("PAUSE", msg.sender);
        designateControl("TREASURY_WITHDRAW", msg.sender);
    }

    /// 🔐 Designate a controller for a specific system function
    function designateControl(string memory controlKey, address controller) public onlySuperAdmin {
        designatedController[keccak256(abi.encodePacked(controlKey))] = controller;
        emit ControlDesignated(controlKey, controller);
    }

    /// 🔐 Revoke a designated controller
    function revokeControl(string memory controlKey) external onlySuperAdmin {
        address oldController = designatedController[keccak256(abi.encodePacked(controlKey))];
        delete designatedController[keccak256(abi.encodePacked(controlKey))];
        emit ControlRevoked(controlKey, oldController);
    }

    /// Example usage: controller must be designated to pause system
    function pauseSystem() external onlyDesignated("PAUSE") {
        // pause logic here
    }

    /// Example usage: controller must be designated to withdraw from treasury
    function withdrawTreasury() external onlyDesignated("TREASURY_WITHDRAW") {
        // withdrawal logic here
    }
}
