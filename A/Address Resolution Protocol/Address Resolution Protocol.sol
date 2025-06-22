// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Address Resolution Protocol (ARP) — Web3 Identity Mapper
contract ARPRegistry {
    address public admin;

    mapping(bytes32 => address) public arpTable;

    event Mapped(bytes32 indexed id, address indexed addr);
    event Cleared(bytes32 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Set ARP record
    function setARP(string calldata namespace, address addr) external onlyAdmin {
        bytes32 id = keccak256(abi.encodePacked(namespace));
        arpTable[id] = addr;
        emit Mapped(id, addr);
    }

    /// Remove ARP record
    function clearARP(string calldata namespace) external onlyAdmin {
        bytes32 id = keccak256(abi.encodePacked(namespace));
        delete arpTable[id];
        emit Cleared(id);
    }

    /// Resolve identity to address
    function resolve(string calldata namespace) external view returns (address) {
        return arpTable[keccak256(abi.encodePacked(namespace))];
    }
}
