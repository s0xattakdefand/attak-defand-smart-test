// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecurityLogManager {
    address public admin;
    mapping(bytes4 => uint256) public selectorHits;
    mapping(address => mapping(bytes4 => uint256)) public callerHits;
    mapping(bytes32 => bool) public knownPayloadHashes;

    event CallLogged(address indexed actor, bytes4 indexed selector, uint256 gasLeft);
    event SuspiciousReplay(address indexed actor, bytes32 payloadHash);
    event SelectorAnomaly(address indexed actor, bytes4 selector, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logCall(bytes calldata data) external {
        require(data.length >= 4, "Invalid call");
        bytes4 selector = bytes4(data[:4]);
        bytes32 payloadHash = keccak256(data);

        emit CallLogged(msg.sender, selector, gasleft());

        selectorHits[selector]++;
        callerHits[msg.sender][selector]++;

        // Replay detection
        if (knownPayloadHashes[payloadHash]) {
            emit SuspiciousReplay(msg.sender, payloadHash);
        } else {
            knownPayloadHashes[payloadHash] = true;
        }

        // Selector anomaly detection
        if (selectorHits[selector] == 1) {
            emit SelectorAnomaly(msg.sender, selector, "First-time selector usage");
        }
    }

    function resetSelector(bytes4 selector) external onlyAdmin {
        selectorHits[selector] = 0;
    }

    function clearPayload(bytes32 hash) external onlyAdmin {
        knownPayloadHashes[hash] = false;
    }

    function getSelectorHits(bytes4 selector) external view returns (uint256) {
        return selectorHits[selector];
    }

    function getCallerSelectorHits(address user, bytes4 selector) external view returns (uint256) {
        return callerHits[user][selector];
    }
}
