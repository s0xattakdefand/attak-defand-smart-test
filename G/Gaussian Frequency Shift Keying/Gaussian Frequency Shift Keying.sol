// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GFSKAttackDefense - Full Attack and Defense Simulation for Gaussian Frequency Shift Keying (GFSK) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Signal Simulation (Vulnerable to Spoofing and Replay)
contract InsecureGFSK {
    mapping(bytes32 => bool) public signals;

    event SignalReceived(address indexed sender, bytes32 signalHash);

    function sendSignal(bytes32 signalHash) external {
        signals[signalHash] = true; // BAD: Accept any signal, no origin/time check
        emit SignalReceived(msg.sender, signalHash);
    }

    function verifySignal(bytes32 signalHash) external view returns (bool) {
        return signals[signalHash];
    }
}

/// @notice Secure Signal Simulation (Nonce + Sender + Time Binding)
contract SecureGFSK {
    address public immutable trustedOrigin;
    mapping(bytes32 => bool) public processedSignals;
    mapping(address => uint256) public nonces;

    event SecureSignalReceived(address indexed sender, bytes32 signalCommitment);

    constructor(address _trustedOrigin) {
        trustedOrigin = _trustedOrigin;
    }

    function sendSecureSignal(bytes32 payload, uint256 nonce, uint256 timestamp, bytes32 signalCommitment) external {
        require(msg.sender == trustedOrigin, "Untrusted source");
        require(block.timestamp <= timestamp + 3 minutes, "Signal expired");
        require(nonce == nonces[msg.sender], "Invalid nonce");

        bytes32 computedCommitment = keccak256(
            abi.encodePacked(msg.sender, payload, nonce, timestamp, address(this))
        );

        require(signalCommitment == computedCommitment, "Signal commitment mismatch");
        require(!processedSignals[signalCommitment], "Replay detected");

        processedSignals[signalCommitment] = true;
        nonces[msg.sender] += 1;

        emit SecureSignalReceived(msg.sender, signalCommitment);
    }
}

/// @notice Attack contract simulating GFSK Spoof and Replay
contract GFSKIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spoofSignal(bytes32 fakeSignal) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("sendSignal(bytes32)", fakeSignal)
        );
    }
}
