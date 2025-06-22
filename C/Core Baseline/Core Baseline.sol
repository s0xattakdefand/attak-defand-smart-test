// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CoreBaselineRegistry {
    address public admin;

    struct BaselineComponent {
        address component;
        bytes32 configHash;
        bool approved;
    }

    mapping(bytes32 => BaselineComponent) public baseline; // key: identifier (e.g., keccak256("Governance"))
    bytes32[] public baselineKeys;

    event BaselineComponentRegistered(bytes32 indexed key, address component, bytes32 configHash);
    event BaselineComponentApproved(bytes32 indexed key, address component);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Register a component with its hash
    function registerBaseline(bytes32 key, address component, bytes32 configHash) external onlyAdmin {
        require(component != address(0), "Invalid address");
        baseline[key] = BaselineComponent(component, configHash, false);
        baselineKeys.push(key);
        emit BaselineComponentRegistered(key, component, configHash);
    }

    // Approve the baseline component after validation (e.g., via audit or off-chain verification)
    function approveBaseline(bytes32 key) external onlyAdmin {
        require(baseline[key].component != address(0), "Component not registered");
        baseline[key].approved = true;
        emit BaselineComponentApproved(key, baseline[key].component);
    }

    // View baseline component details
    function getBaseline(bytes32 key) external view returns (address, bytes32, bool) {
        BaselineComponent memory b = baseline[key];
        return (b.component, b.configHash, b.approved);
    }

    // Retrieve all baseline keys
    function listAllKeys() external view returns (bytes32[] memory) {
        return baselineKeys;
    }
}
