// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AllSourceIntelHub {
    struct IntelSignal {
        address source;
        bytes32 signalHash;
        uint8 severity;
        uint256 timestamp;
    }

    mapping(bytes32 => bool) public usedHashes;
    mapping(address => bool) public trustedSources;
    mapping(bytes32 => IntelSignal[]) public signalPool;

    uint8 public constant QUORUM_THRESHOLD = 2; // Example: need 2 sources to confirm

    event IntelReceived(address indexed source, bytes32 indexed targetId, uint8 severity);
    event QuorumReached(bytes32 indexed targetId, uint8 combinedSeverity, string actionTaken);

    constructor(address[] memory initialSources) {
        for (uint i = 0; i < initialSources.length; i++) {
            trustedSources[initialSources[i]] = true;
        }
    }

    modifier onlyTrusted() {
        require(trustedSources[msg.sender], "Untrusted source");
        _;
    }

    function submitIntel(bytes32 targetId, uint8 severity, string calldata reason) external onlyTrusted {
        bytes32 hash = keccak256(abi.encodePacked(targetId, severity, reason, msg.sender));
        require(!usedHashes[hash], "Duplicate signal");

        IntelSignal memory signal = IntelSignal({
            source: msg.sender,
            signalHash: hash,
            severity: severity,
            timestamp: block.timestamp
        });

        signalPool[targetId].push(signal);
        usedHashes[hash] = true;

        emit IntelReceived(msg.sender, targetId, severity);

        if (signalPool[targetId].length >= QUORUM_THRESHOLD) {
            uint8 combined = _calculateSeverity(signalPool[targetId]);
            emit QuorumReached(targetId, combined, reason);
            // Take defensive action here (e.g., freeze, flag)
        }
    }

    function _calculateSeverity(IntelSignal[] memory signals) internal pure returns (uint8 total) {
        for (uint i = 0; i < signals.length; i++) {
            total += signals[i].severity;
        }
        return total / uint8(signals.length);
    }

    function isSourceTrusted(address source) external view returns (bool) {
        return trustedSources[source];
    }

    function getSignalsForTarget(bytes32 targetId) external view returns (IntelSignal[] memory) {
        return signalPool[targetId];
    }
}
