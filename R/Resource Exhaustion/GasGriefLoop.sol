// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IThreatUplink {
    function logThreat(string calldata module, string calldata detail, uint256 gasUsed) external;
}

contract GasGriefLoop {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function burnGas(uint256 rounds) external {
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < rounds; ++i) {
            assembly { let x := i }
        }
        uint256 used = g0 - gasleft();
        uplink.logThreat("GasGriefLoop", "High gas loop triggered", used);
    }
}
