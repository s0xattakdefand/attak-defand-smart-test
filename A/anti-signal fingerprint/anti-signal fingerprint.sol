// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiSignalFingerprintScanner {
    struct Signal {
        bytes4 selector;
        uint256 gasUsed;
        bytes32 calldataHash;
    }

    mapping(address => Signal[]) public fingerprintLog;
    mapping(address => bool) public flagged;
    uint256 public driftThreshold = 3;

    event FingerprintLogged(address indexed source, bytes4 selector, uint256 gasUsed, bytes32 calldataHash);
    event AntiSignalAlert(address indexed source, string reason);

    function logExecution(bytes calldata payload) external {
        uint256 startGas = gasleft();
        bytes4 selector;
        bytes32 calldataHash = keccak256(payload);

        assembly {
            selector := calldataload(payload.offset)
        }

        uint256 used = startGas - gasleft();
        Signal memory sig = Signal(selector, used, calldataHash);

        fingerprintLog[msg.sender].push(sig);
        emit FingerprintLogged(msg.sender, selector, used, calldataHash);

        if (_checkAnomaly(msg.sender)) {
            flagged[msg.sender] = true;
            emit AntiSignalAlert(msg.sender, "Pattern drift / anti-fingerprint behavior detected");
        }
    }

    function _checkAnomaly(address src) internal view returns (bool) {
        Signal[] memory logs = fingerprintLog[src];
        if (logs.length < driftThreshold) return false;

        bytes4 base = logs[0].selector;
        for (uint i = 1; i < logs.length; i++) {
            if (logs[i].selector != base) return true;
        }

        return false;
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }

    function getSignalLog(address user) external view returns (Signal[] memory) {
        return fingerprintLog[user];
    }
}
