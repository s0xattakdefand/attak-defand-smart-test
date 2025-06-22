// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GapSVPAttackDefense - Full Attack and Defense Simulation for Gap Shortest Vector Problem in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Commitment System (Vulnerable to Lattice Reduction Attack)
contract InsecureGapSVP {
    mapping(address => bytes32) public commitments;

    event CommitmentMade(address indexed user, bytes32 commitment);

    function commit(bytes32 vectorHash) external {
        commitments[msg.sender] = vectorHash; // BAD: Simple hash, no randomness included
        emit CommitmentMade(msg.sender, vectorHash);
    }

    function verify(address user, bytes32 guessedVector) external view returns (bool) {
        return commitments[user] == guessedVector;
    }
}

/// @notice Secure Gap-SVP Simulated Commitment System (Randomized and Non-Reusable)
contract SecureGapSVP {
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public committed;
    mapping(address => uint256) public randomnessNonces;

    event SecureCommitmentMade(address indexed user, bytes32 commitment, uint256 nonce);

    function secureCommit(bytes32 latticeVector, uint256 randomNonce) external {
        require(!committed[msg.sender], "Already committed");
        
        // Tight binding: vector + nonce + sender + contract address
        bytes32 commitment = keccak256(
            abi.encodePacked(latticeVector, randomNonce, msg.sender, address(this))
        );
        
        commitments[msg.sender] = commitment;
        committed[msg.sender] = true;
        randomnessNonces[msg.sender] = randomNonce;

        emit SecureCommitmentMade(msg.sender, commitment, randomNonce);
    }

    function verifyCommitment(address user, bytes32 latticeVector, uint256 randomNonce) external view returns (bool) {
        bytes32 expected = keccak256(
            abi.encodePacked(latticeVector, randomNonce, user, address(this))
        );
        return commitments[user] == expected;
    }
}

/// @notice Attack contract trying to guess or replay vectors
contract GapSVPIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeCommit(bytes32 guessedVector) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("commit(bytes32)", guessedVector)
        );
    }
}
