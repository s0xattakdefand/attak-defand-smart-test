// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousScriptInjectionAttackDefense - Full Attack and Defense Simulation for Malicious Script Injection on Frontend via Smart Contracts
/// @author ChatGPT

/// @notice Secure contract sanitizing user input to prevent front-end injection
contract SecureFrontEndStorage {
    address public owner;
    uint256 public constant MAX_STRING_LENGTH = 256;

    mapping(address => string) private userProfiles;

    event ProfileUpdated(address indexed user, string sanitizedProfile);

    constructor() {
        owner = msg.sender;
    }

    modifier sanitizeInput(string memory _input) {
        bytes memory inputBytes = bytes(_input);
        require(inputBytes.length > 0 && inputBytes.length <= MAX_STRING_LENGTH, "Invalid input length");

        for (uint256 i = 0; i < inputBytes.length; i++) {
            // Disallow '<' (0x3C), '>' (0x3E), '"' (0x22), '\'' (0x27)
            require(
                inputBytes[i] != 0x3C &&
                inputBytes[i] != 0x3E &&
                inputBytes[i] != 0x22 &&
                inputBytes[i] != 0x27,
                "Dangerous character detected"
            );
        }
        _;
    }

    function updateProfile(string calldata _profileText) external sanitizeInput(_profileText) {
        userProfiles[msg.sender] = _profileText;
        emit ProfileUpdated(msg.sender, _profileText);
    }

    function getProfile(address user) external view returns (string memory) {
        return userProfiles[user];
    }
}

/// @notice Attack contract trying to inject malicious scripts into frontend through storage
contract ScriptInjectionIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryInjectMaliciousProfile(string calldata payload) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("updateProfile(string)", payload)
        );
    }
}
