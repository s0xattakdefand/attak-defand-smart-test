// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfigurationBaselineEnforcer {
    address public admin;
    bytes32 public immutable baselineHash;
    mapping(bytes32 => bool) public approvedChanges;

    event ConfigChangeProposed(bytes32 indexed newHash, address indexed proposer);
    event ConfigChangeApproved(bytes32 indexed newHash, address indexed approver);
    event DriftDetected(bytes32 indexed driftHash, address actor);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(bytes32 _baselineHash) {
        admin = msg.sender;
        baselineHash = _baselineHash;
    }

    function proposeChange(bytes calldata configBlob) external {
        bytes32 newHash = keccak256(configBlob);
        emit ConfigChangeProposed(newHash, msg.sender);
    }

    function approveChange(bytes calldata configBlob) external onlyAdmin {
        bytes32 newHash = keccak256(configBlob);
        approvedChanges[newHash] = true;
        emit ConfigChangeApproved(newHash, msg.sender);
    }

    function validateCurrent(bytes calldata currentConfig) external view returns (bool) {
        bytes32 hash = keccak256(currentConfig);
        return hash == baselineHash || approvedChanges[hash];
    }

    function enforce(bytes calldata currentConfig) external view {
        bytes32 hash = keccak256(currentConfig);
        require(hash == baselineHash || approvedChanges[hash], "Baseline drift detected");
    }
}
