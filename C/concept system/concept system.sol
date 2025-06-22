// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Interface for logic module
interface ILogicModule {
    function executeLogic(uint256 input) external pure returns (uint256);
}

// Safe logic module
contract SafeLogic is ILogicModule {
    function executeLogic(uint256 input) external pure override returns (uint256) {
        return input * 2;
    }
}

// Malicious logic module (attacker tries to inject this)
contract MaliciousLogic is ILogicModule {
    function executeLogic(uint256 input) external pure override returns (uint256) {
        return 0; // Always fail logic
    }
}

// Concept System manager
contract ConceptSystem {
    address public owner;
    ILogicModule public logicModule;

    event LogicExecuted(uint256 input, uint256 output);
    event ModuleUpgraded(address newModule);

    constructor(address _logicModule) {
        owner = msg.sender;
        logicModule = ILogicModule(_logicModule);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function upgradeLogicModule(address _newModule) external onlyOwner {
        require(_newModule.code.length > 0, "Invalid module");
        logicModule = ILogicModule(_newModule);
        emit ModuleUpgraded(_newModule);
    }

    function execute(uint256 input) external returns (uint256) {
        uint256 result = logicModule.executeLogic(input);
        emit LogicExecuted(input, result);
        return result;
    }

    // Defense: lock upgrade path with hashed config
    bytes32 public upgradeAuthHash;

    function setUpgradeAuthHash(bytes32 hash) external onlyOwner {
        upgradeAuthHash = hash;
    }

    function secureUpgradeLogicModule(address _newModule, string memory passphrase) external onlyOwner {
        require(keccak256(abi.encodePacked(passphrase)) == upgradeAuthHash, "Unauthorized upgrade");
        logicModule = ILogicModule(_newModule);
        emit ModuleUpgraded(_newModule);
    }
}
