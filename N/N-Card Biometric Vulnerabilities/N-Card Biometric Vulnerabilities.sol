// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NCardBiometricComparisonAttackDefense - Attack and Defense Simulation for N-Card Biometric Comparison in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Biometric Matching (Static Hash Comparison, No Nonce, No Session Expiry)
contract InsecureBiometricMatcher {
    mapping(address => bytes32) public registeredBiometricHash;

    event UserRegistered(address indexed user, bytes32 biometricHash);
    event BiometricMatched(address indexed user);

    function registerBiometric(bytes32 biometricHash) external {
        registeredBiometricHash[msg.sender] = biometricHash;
        emit UserRegistered(msg.sender, biometricHash);
    }

    function matchBiometric(bytes32 biometricProof) external view returns (bool) {
        return registeredBiometricHash[msg.sender] == biometricProof;
    }
}

/// @notice Secure Biometric Matching (Nonce-Protected, Time-Bound, zk-Compatible Commitments)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBiometricMatcher is Ownable {
    mapping(address => bytes32) private registeredCommitments;
    mapping(address => uint256) public sessionNonces;
    mapping(address => uint256) public sessionExpiry;

    uint256 public constant SESSION_DURATION = 5 minutes;

    event UserRegistered(address indexed user, bytes32 commitment);
    event SessionStarted(address indexed user, uint256 nonce, uint256 expiry);
    event BiometricMatched(address indexed user);

    function registerCommitment(bytes32 commitment) external {
        require(registeredCommitments[msg.sender] == bytes32(0), "Already registered");
        registeredCommitments[msg.sender] = commitment;
        emit UserRegistered(msg.sender, commitment);
    }

    function startSession() external {
        sessionNonces[msg.sender] = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender, blockhash(block.number-1))));
        sessionExpiry[msg.sender] = block.timestamp + SESSION_DURATION;
        emit SessionStarted(msg.sender, sessionNonces[msg.sender], sessionExpiry[msg.sender]);
    }

    function matchBiometric(bytes32 proofCommitment) external returns (bool) {
        require(block.timestamp <= sessionExpiry[msg.sender], "Session expired");
        require(registeredCommitments[msg.sender] != bytes32(0), "Not registered");

        bytes32 expectedCommitment = keccak256(abi.encodePacked(registeredCommitments[msg.sender], sessionNonces[msg.sender]));

        bool matched = (proofCommitment == expectedCommitment);

        if (matched) {
            emit BiometricMatched(msg.sender);
        }

        // Invalidate session after match attempt
        sessionNonces[msg.sender] = 0;
        sessionExpiry[msg.sender] = 0;

        return matched;
    }
}

/// @notice Attack contract simulating replay attack on insecure matcher
contract BiometricIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replayBiometric(bytes32 stolenHash) external view returns (bool success) {
        (success, ) = targetInsecure.staticcall(
            abi.encodeWithSignature("matchBiometric(bytes32)", stolenHash)
        );
    }
}
