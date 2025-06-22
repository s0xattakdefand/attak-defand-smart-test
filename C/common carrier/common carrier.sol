// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonCarrierRegistry {
    address public admin;

    struct Carrier {
        string name;
        bool active;
    }

    mapping(address => Carrier) public carriers;
    mapping(bytes32 => bool) public deliveredHashes; // prevent duplicates

    event CarrierRegistered(address indexed carrier, string name);
    event CarrierStatusChanged(address indexed carrier, bool active);
    event PayloadRelayed(address indexed carrier, address indexed user, bytes32 payloadHash, string meta, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier onlyCarrier() {
        require(carriers[msg.sender].active, "Not an active carrier");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerCarrier(address carrier, string calldata name) external onlyAdmin {
        carriers[carrier] = Carrier(name, true);
        emit CarrierRegistered(carrier, name);
    }

    function setCarrierStatus(address carrier, bool active) external onlyAdmin {
        require(bytes(carriers[carrier].name).length > 0, "Carrier not found");
        carriers[carrier].active = active;
        emit CarrierStatusChanged(carrier, active);
    }

    function relayPayload(address user, bytes calldata payload, string calldata meta) external onlyCarrier {
        bytes32 hash = keccak256(payload);
        require(!deliveredHashes[hash], "Payload already relayed");

        deliveredHashes[hash] = true;

        emit PayloadRelayed(msg.sender, user, hash, meta, block.timestamp);
    }

    // Public verification
    function isPayloadDelivered(bytes calldata payload) external view returns (bool) {
        return deliveredHashes[keccak256(payload)];
    }
}
