// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CoreRootOfTrust {
    address public admin;
    bool public sealed;

    struct Measurement {
        bytes32 configHash;
        uint256 timestamp;
        address measuredBy;
    }

    mapping(bytes32 => Measurement) public measurements;
    bytes32[] public measurementKeys;

    event Measured(bytes32 indexed id, bytes32 configHash, address indexed by);
    event Sealed();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notSealed() {
        require(!sealed, "CRTM sealed");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Record a measurement hash before sealing
    function measure(bytes32 id, bytes32 configHash) external onlyAdmin notSealed {
        require(measurements[id].timestamp == 0, "Already measured");
        measurements[id] = Measurement(configHash, block.timestamp, msg.sender);
        measurementKeys.push(id);
        emit Measured(id, configHash, msg.sender);
    }

    /// Seal CRTM (finalize measurements)
    function seal() external onlyAdmin {
        sealed = true;
        emit Sealed();
    }

    /// Public verifier function
    function verify(bytes32 id, bytes32 inputHash) external view returns (bool valid) {
        return measurements[id].configHash == inputHash;
    }

    /// View all measurement keys
    function getAllMeasuredIds() external view returns (bytes32[] memory) {
        return measurementKeys;
    }
}
