// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IThreatUplink {
    function logThreat(string calldata module, string calldata detail, uint256 metric) external;
}

contract DoSComboSimulator {
    IThreatUplink public uplink;

    struct Payload {
        uint256[10] pad;
        mapping(uint256 => uint256) store;
    }

    mapping(address => Payload) private userStore;

    event SpamLog(address sender, uint256 i);

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    fallback() external payable {
        uplink.logThreat("FallbackDrift", "Entropy selector hit", gasleft());
    }

    function comboBlast(uint256 writes, uint256 logs) external {
        // memory pressure
        for (uint256 i = 0; i < writes; i++) {
            userStore[msg.sender].pad[i % 10] = i;
            userStore[msg.sender].store[i] = block.timestamp;
        }

        // event flood
        for (uint256 j = 0; j < logs; j++) {
            emit SpamLog(msg.sender, j);
        }

        uplink.logThreat("ComboStress", "Memory+Logs combo executed", writes + logs);
    }
}
