// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CNSSController {
    address public admin;
    bytes32 public configHash;

    mapping(address => bool) public operators;

    event ConfigInitialized(bytes32 indexed configHash);
    event OperatorAdded(address indexed operator);
    event OperatorRemoved(address indexed operator);
    event ActionExecuted(address indexed by, string action);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CNSS: Not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "CNSS: Not operator");
        _;
    }

    modifier configCheck(bytes32 _hash) {
        require(_hash == configHash, "CNSS: Invalid config");
        _;
    }

    constructor(bytes32 _configHash) {
        admin = msg.sender;
        configHash = _configHash;
        emit ConfigInitialized(_configHash);
    }

    function addOperator(address user) external onlyAdmin {
        operators[user] = true;
        emit OperatorAdded(user);
    }

    function removeOperator(address user) external onlyAdmin {
        operators[user] = false;
        emit OperatorRemoved(user);
    }

    // Example sensitive function
    function executeSecuredAction(string calldata actionLabel, bytes32 _configHash)
        external
        onlyOperator
        configCheck(_configHash)
    {
        emit ActionExecuted(msg.sender, actionLabel);
        // Action logic here (e.g., deploy upgrade, interact with external module)
    }

    // Config hash validation support
    function getConfigHash() external view returns (bytes32) {
        return configHash;
    }

    function updateConfigHash(bytes32 newHash) external onlyAdmin {
        configHash = newHash;
        emit ConfigInitialized(newHash);
    }
}
