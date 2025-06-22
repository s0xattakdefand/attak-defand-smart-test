// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Addressable Registry — Tracks which entities are recognized and routed
contract AddressableRegistry {
    address public admin;

    struct Addressable {
        string label;
        string kind;
        uint256 registeredAt;
        bool exists;
    }

    mapping(address => Addressable) public registry;

    event AddressableRegistered(address indexed addr, string kind, string label);
    event AddressableRemoved(address indexed addr);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function register(address addr, string calldata kind, string calldata label) external onlyAdmin {
        registry[addr] = Addressable(label, kind, block.timestamp, true);
        emit AddressableRegistered(addr, kind, label);
    }

    function remove(address addr) external onlyAdmin {
        delete registry[addr];
        emit AddressableRemoved(addr);
    }

    function isAddressable(address addr) external view returns (bool) {
        return registry[addr].exists;
    }

    function getAddressable(address addr) external view returns (Addressable memory) {
        return registry[addr];
    }
}
