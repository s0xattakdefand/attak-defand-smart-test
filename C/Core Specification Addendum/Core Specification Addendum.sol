// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICoreAddendum {
    function applySpec(address user, bytes calldata data) external returns (bool);
}

contract CoreSpecController {
    address public admin;

    mapping(bytes32 => address) public approvedAddenda; // key: keccak256(addendumName)
    event AddendumApproved(bytes32 indexed nameHash, address indexed contractAddress);
    event AddendumInvoked(bytes32 indexed nameHash, address user, bool result);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function approveAddendum(string calldata name, address addendum) external onlyAdmin {
        require(addendum != address(0), "Invalid address");
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        approvedAddenda[nameHash] = addendum;
        emit AddendumApproved(nameHash, addendum);
    }

    function invokeAddendum(string calldata name, bytes calldata data) external returns (bool) {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        address addendum = approvedAddenda[nameHash];
        require(addendum != address(0), "Addendum not approved");

        bool result = ICoreAddendum(addendum).applySpec(msg.sender, data);
        emit AddendumInvoked(nameHash, msg.sender, result);
        return result;
    }

    function getAddendum(string calldata name) external view returns (address) {
        return approvedAddenda[keccak256(abi.encodePacked(name))];
    }
}
