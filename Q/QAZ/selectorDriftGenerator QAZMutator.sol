// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract QAZMutator {
    event DriftedSelector(bytes4 drifted, uint256 entropy);

    function mutateSelector(uint256 seed) external returns (bytes4) {
        bytes4 sel = bytes4(keccak256(abi.encodePacked(seed, block.timestamp, msg.sender)));
        emit DriftedSelector(sel, uint256(uint32(sel)));
        return sel;
    }

    function batchMutate(uint8 count) external returns (bytes4[] memory selectors) {
        selectors = new bytes4[](count);
        for (uint8 i = 0; i < count; i++) {
            selectors[i] = mutateSelector(i);
        }
    }
}
