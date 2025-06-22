// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MasterKeyAttackDefense - Full Attack and Defense Simulation for Master Key Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Master Key System (Single-Point Master Key Without Control)
contract InsecureMasterKey {
    address public masterKey;

    event MasterActionExecuted(address indexed executor, string action);

    constructor(address _masterKey) {
        masterKey = _masterKey;
    }

    function emergencyAction(string calldata action) external {
        require(msg.sender == masterKey, "Only master key");
        emit MasterActionExecuted(msg.sender, action);
        // BAD: No rotation, no secondary verification, unlimited scope
    }
}

/// @notice Secure Master Key System (Multi-Sig + Rotation + Scoped Emergency Actions)
contract SecureMasterKey {
    address public owner;
    address public masterKey;
    mapping(address => bool) public authorizedSigners;
    uint256 public constant REQUIRED_CONFIRMATIONS = 2;
    mapping(bytes32 => uint256) public confirmations;

    event MasterKeyRotated(address indexed newMasterKey);
    event MasterEmergencyActionProposed(bytes32 indexed actionHash, address proposer);
    event MasterEmergencyActionConfirmed(bytes32 indexed actionHash, address confirmer);
    event MasterEmergencyActionExecuted(string action);

    constructor(address _initialMasterKey, address[] memory _authorizedSigners) {
        owner = msg.sender;
        masterKey = _initialMasterKey;
        for (uint256 i = 0; i < _authorizedSigners.length; i++) {
            authorizedSigners[_authorizedSigners[i]] = true;
        }
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedSigners[msg.sender], "Not authorized signer");
        _;
    }

    function proposeEmergencyAction(string calldata action) external onlyAuthorized {
        bytes32 actionHash = keccak256(abi.encodePacked(action));
        require(confirmations[actionHash] == 0, "Action already proposed");
        confirmations[actionHash] = 1;
        emit MasterEmergencyActionProposed(actionHash, msg.sender);
    }

    function confirmEmergencyAction(string calldata action) external onlyAuthorized {
        bytes32 actionHash = keccak256(abi.encodePacked(action));
        require(confirmations[actionHash] > 0, "Action not proposed");
        require(confirmations[actionHash] < REQUIRED_CONFIRMATIONS, "Already confirmed");

        confirmations[actionHash] += 1;
        emit MasterEmergencyActionConfirmed(actionHash, msg.sender);

        if (confirmations[actionHash] == REQUIRED_CONFIRMATIONS) {
            emit MasterEmergencyActionExecuted(action);
            delete confirmations[actionHash]; // Cleanup after execution
        }
    }

    function rotateMasterKey(address newMasterKey) external onlyOwner {
        masterKey = newMasterKey;
        emit MasterKeyRotated(newMasterKey);
    }
}

/// @notice Attack contract simulating unauthorized master key abuse
contract MasterKeyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function abuseMasterAccess(string calldata maliciousAction) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("emergencyAction(string)", maliciousAction)
        );
    }
}
