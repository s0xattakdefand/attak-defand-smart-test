// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiSignalSpoofGuard {
    struct SignalProfile {
        bytes4 selector;
        bytes32 payloadHash;
        uint256 entropy;
        uint256 gasUsed;
        uint256 timestamp;
    }

    mapping(address => SignalProfile[]) public activityLog;
    mapping(address => bool) public flagged;

    uint256 public spoofEntropyThreshold = 16; // Lower = more predictable
    uint256 public selectorDriftLimit = 3;

    event SpoofDetected(address indexed source, string reason);
    event SignalLogged(address indexed source, bytes4 selector, uint256 entropy, uint256 gasUsed);

    function logSignal(bytes calldata payload) external {
        uint256 gasStart = gasleft();
        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }

        uint256 gasUsed = gasStart - gasleft();
        bytes32 hash = keccak256(payload);
        uint256 entropy = _estimateEntropy(payload);

        SignalProfile memory profile = SignalProfile({
            selector: selector,
            payloadHash: hash,
            entropy: entropy,
            gasUsed: gasUsed,
            timestamp: block.timestamp
        });

        activityLog[msg.sender].push(profile);
        emit SignalLogged(msg.sender, selector, entropy, gasUsed);

        if (_detectSpoof(msg.sender)) {
            flagged[msg.sender] = true;
            emit SpoofDetected(msg.sender, "Anti-signal spoof pattern detected");
        }
    }

    function _detectSpoof(address user) internal view returns (bool) {
        SignalProfile[] memory logs = activityLog[user];
        if (logs.length < selectorDriftLimit) return false;

        bytes4 baseSelector = logs[0].selector;
        uint256 selectorDrift = 0;
        uint256 avgEntropy = 0;

        for (uint i = 0; i < logs.length; i++) {
            if (logs[i].selector != baseSelector) selectorDrift++;
            avgEntropy += logs[i].entropy;
        }

        avgEntropy /= logs.length;

        return (selectorDrift >= selectorDriftLimit && avgEntropy < spoofEntropyThreshold);
    }

    function _estimateEntropy(bytes memory data) internal pure returns (uint256 score) {
        bool[256] memory seen;
        for (uint i = 0; i < data.length; i++) {
            seen[uint8(data[i])] = true;
        }
        for (uint i = 0; i < 256; i++) {
            if (seen[i]) score++;
        }
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }

    function getLogs(address user) external view returns (SignalProfile[] memory) {
        return activityLog[user];
    }

    function setThresholds(uint256 entropyThreshold, uint256 driftLimit) external {
        spoofEntropyThreshold = entropyThreshold;
        selectorDriftLimit = driftLimit;
    }
}
