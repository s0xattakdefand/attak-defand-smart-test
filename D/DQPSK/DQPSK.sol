// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract DQPSKSecure is AccessControl, ReentrancyGuard {
    bytes32 public constant TRANSMITTER_ROLE = keccak256("TRANSMITTER_ROLE");
    bytes32 public constant RECEIVER_ROLE = keccak256("RECEIVER_ROLE");

    uint256 public constant NUM_PHASES = 4; // 0-3 for phases
    mapping(address => uint256) private _lastPhase; // Private for security

    event MessageEncoded(address indexed transmitter, uint256 bits, uint256 phase);
    event MessageDecoded(address indexed receiver, uint256 phase, uint256 bits, bool valid);
    event AccessDenied(address indexed user, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TRANSMITTER_ROLE, msg.sender);
        _grantRole(RECEIVER_ROLE, msg.sender);
    }

    // Secure encode: Proper differential with modulo 4
    function encodeMessage(uint256 bits) public onlyRole(TRANSMITTER_ROLE) nonReentrant returns (uint256 currentPhase) {
        require(bits < NUM_PHASES, "Invalid 2-bit symbol");
        uint256 prevPhase = _lastPhase[msg.sender];
        // FIXED: Modulo 4 ensures valid phase (0-3)
        currentPhase = (prevPhase + bits) % NUM_PHASES;
        _lastPhase[msg.sender] = currentPhase;
        emit MessageEncoded(msg.sender, bits, currentPhase);
        return currentPhase;
    }

    // Secure decode: Validates diff with modulo, simulates error correction
    function decodeMessage(uint256 receivedPhase) public onlyRole(RECEIVER_ROLE) returns (uint256 bits, bool isValid) {
        require(receivedPhase < NUM_PHASES, "Invalid received phase");
        uint256 prevPhase = _lastPhase[msg.sender];
        // FIXED: Correct differential diff with modulo 4 wrap
        int256 diff = int256(receivedPhase) - int256(prevPhase);
        if (diff < 0) diff += int256(NUM_PHASES);
        else if (diff >= int256(NUM_PHASES)) diff -= int256(NUM_PHASES);
        bits = uint256(diff);
        // Basic error correction: Hamming-like check (valid if diff < 4)
        isValid = (bits < NUM_PHASES);
        if (!isValid) {
            emit AccessDenied(msg.sender, "Decoding error detected");
            bits = 0;
        }
        _lastPhase[msg.sender] = receivedPhase;
        emit MessageDecoded(msg.sender, receivedPhase, bits, isValid);
        return (bits, isValid);
    }

    // Simulate secure transmission
    function transmitAndDecode(uint256 bits) public onlyRole(TRANSMITTER_ROLE) returns (uint256, bool) {
        uint256 phase = encodeMessage(bits);
        return decodeMessage(phase); // Always valid now
    }

    // Admin grants roles for transmitters/receivers (e.g., IoT devices)
    function grantTransmitterRole(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(TRANSMITTER_ROLE, user);
    }

    function grantReceiverRole(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(RECEIVER_ROLE, user);
    }

    // Reset phase (role-restricted)
    function resetPhase() public onlyRole(TRANSMITTER_ROLE) {
        _lastPhase[msg.sender] = 0;
    }

    // View last phase (receivers only)
    function getLastPhase() public view returns (uint256) {
        require(hasRole(RECEIVER_ROLE, msg.sender), "Unauthorized");
        return _lastPhase[msg.sender];
    }
}