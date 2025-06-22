// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BusinessAreaAttackDefense - Attack and Defense Simulation for Business Areas in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Business Area Management (No Isolation, No Access Control)
contract InsecureBusinessArea {
    mapping(string => address) public areaOwners;
    mapping(string => uint256) public areaFunds;

    event AreaFunded(string indexed area, uint256 amount);
    event AreaOwnerChanged(string indexed area, address indexed newOwner);

    function fundArea(string calldata area) external payable {
        areaFunds[area] += msg.value;
        emit AreaFunded(area, msg.value);
    }

    function changeAreaOwner(string calldata area, address newOwner) external {
        // 🔥 No ownership check!
        areaOwners[area] = newOwner;
        emit AreaOwnerChanged(area, newOwner);
    }

    function withdrawAreaFunds(string calldata area, uint256 amount) external {
        areaFunds[area] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

/// @notice Secure Business Area Management with Role Segmentation, Resource Isolation, and Immutable Area Ownership
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureBusinessArea is AccessControl {
    bytes32 public constant AREA_ADMIN_ROLE = keccak256("AREA_ADMIN_ROLE");

    struct BusinessArea {
        address owner;
        uint256 funds;
        bool initialized;
    }

    mapping(string => BusinessArea) private areas;

    event AreaInitialized(string indexed area, address indexed owner);
    event AreaFunded(string indexed area, uint256 amount);
    event AreaWithdrawal(string indexed area, address indexed recipient, uint256 amount);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AREA_ADMIN_ROLE, admin);
    }

    function initializeArea(string calldata area, address owner) external onlyRole(AREA_ADMIN_ROLE) {
        require(!areas[area].initialized, "Area already initialized");
        areas[area] = BusinessArea({
            owner: owner,
            funds: 0,
            initialized: true
        });

        emit AreaInitialized(area, owner);
    }

    function fundArea(string calldata area) external payable {
        require(areas[area].initialized, "Area not initialized");
        areas[area].funds += msg.value;
        emit AreaFunded(area, msg.value);
    }

    function withdrawAreaFunds(string calldata area, uint256 amount) external {
        BusinessArea storage ba = areas[area];
        require(ba.initialized, "Area not initialized");
        require(msg.sender == ba.owner, "Not area owner");
        require(ba.funds >= amount, "Insufficient area funds");

        ba.funds -= amount;
        payable(msg.sender).transfer(amount);

        emit AreaWithdrawal(area, msg.sender, amount);
    }

    function getAreaInfo(string calldata area) external view returns (address owner, uint256 funds) {
        BusinessArea memory ba = areas[area];
        return (ba.owner, ba.funds);
    }

    receive() external payable {}
}

/// @notice Intruder trying to hijack area ownership and drain funds
contract BusinessAreaIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeChangeOwner(string calldata area, address fakeOwner) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("changeAreaOwner(string,address)", area, fakeOwner)
        );
    }

    function unauthorizedWithdraw(string calldata area, uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdrawAreaFunds(string,uint256)", area, amount)
        );
    }
}
