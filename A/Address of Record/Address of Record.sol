// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Address of Record (AOR) Registry
contract AORRegistry {
    address public admin;

    // Identity ID (e.g. ENS name hash or zkID) → AOR
    mapping(bytes32 => address) public addressOfRecord;

    event AORUpdated(bytes32 indexed identityId, address newAOR);
    event AORCleared(bytes32 indexed identityId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Set or update AOR
    function setAOR(bytes32 identityId, address aor) external onlyAdmin {
        addressOfRecord[identityId] = aor;
        emit AORUpdated(identityId, aor);
    }

    /// Remove AOR binding
    function clearAOR(bytes32 identityId) external onlyAdmin {
        delete addressOfRecord[identityId];
        emit AORCleared(identityId);
    }

    /// Resolve canonical address
    function resolve(bytes32 identityId) external view returns (address) {
        return addressOfRecord[identityId];
    }
}
