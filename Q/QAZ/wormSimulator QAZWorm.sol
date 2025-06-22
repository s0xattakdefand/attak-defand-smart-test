// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract QAZWorm {
    mapping(address => bool) public infected;
    address[] public spread;

    event Infection(address indexed victim);
    event FallbackExecuted(address indexed origin, bytes data);

    // 🧠 Try infecting fallback-based targets
    function spreadTo(address target) external {
        for (uint8 i = 0; i < 4; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(i, block.timestamp, target)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            if (ok && !infected[target]) {
                infected[target] = true;
                spread.push(target);
                emit Infection(target);
            }
        }
    }

    // 🕳️ Fallback-style remote control (QAZ backdoor)
    fallback() external payable {
        emit FallbackExecuted(tx.origin, msg.data);
        // hidden logic, delegatecall, or admin override here
    }
}
