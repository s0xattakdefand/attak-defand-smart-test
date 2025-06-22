// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract OctetDriftFuzzer {
    event DriftCall(address target, bytes4 drift, bool success);

    function fuzz(address target, uint8 rounds) external {
        for (uint8 i = 0; i < rounds; i++) {
            bytes4 selector = bytes4(
                uint32(
                    uint8(block.timestamp + i) << 24 |
                    uint8(block.difficulty) << 16 |
                    uint8(msg.sender) << 8 |
                    i
                )
            );

            (bool ok, ) = target.call(abi.encodePacked(selector));
            emit DriftCall(target, selector, ok);
        }
    }
}
