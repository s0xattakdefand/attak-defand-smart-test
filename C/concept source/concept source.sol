// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Oracle Interface
interface IConceptSource {
    function getValue() external view returns (uint256);
}

// Attack Simulation (malicious source)
contract MaliciousSource is IConceptSource {
    function getValue() external pure override returns (uint256) {
        return 1000000; // Exaggerated price/value
    }
}

// Secure Oracle Source
contract SecureSource is IConceptSource {
    uint256 public value;
    address public updater;

    constructor() {
        updater = msg.sender;
    }

    function updateValue(uint256 newValue) external {
        require(msg.sender == updater, "Unauthorized");
        value = newValue;
    }

    function getValue() external view override returns (uint256) {
        return value;
    }
}

// Main Contract using Concept Source
contract ConceptLogicConsumer {
    address public owner;
    IConceptSource public conceptSource;
    mapping(address => bool) public trustedSources;

    constructor(address _conceptSource) {
        owner = msg.sender;
        conceptSource = IConceptSource(_conceptSource);
        trustedSources[_conceptSource] = true;
    }

    function setConceptSource(address _source) external {
        require(msg.sender == owner, "Only owner");
        require(trustedSources[_source], "Untrusted source");
        conceptSource = IConceptSource(_source);
    }

    function trustSource(address _source, bool isTrusted) external {
        require(msg.sender == owner, "Only owner");
        trustedSources[_source] = isTrusted;
    }

    function executeBasedOnSource() external view returns (string memory) {
        uint256 value = conceptSource.getValue();
        if (value > 1000) {
            return "High value logic triggered";
        } else {
            return "Default logic triggered";
        }
    }
}
