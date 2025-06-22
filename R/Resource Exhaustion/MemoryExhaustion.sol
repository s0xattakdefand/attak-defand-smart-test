// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IThreatUplink {
    function logThreat(string calldata module, string calldata detail, uint256 resource) external;
}

contract MemoryExhaustion {
    struct DeepStruct {
        uint256[10] pad;
        mapping(uint256 => uint256) innerMap;
    }

    mapping(address => DeepStruct) private bloater;
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function bloat(uint256 writes) external {
        for (uint256 i = 0; i < writes; i++) {
            bloater[msg.sender].pad[i % 10] = block.number;
            bloater[msg.sender].innerMap[i] = i + block.timestamp;
        }
        uplink.logThreat("MemoryExhaustion", "Heavy nested writes", writes);
    }
}
