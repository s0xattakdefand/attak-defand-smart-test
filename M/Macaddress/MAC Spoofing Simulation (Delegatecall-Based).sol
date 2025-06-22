// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Victim {
    address public lastCaller;

    function sensitiveLogic() external {
        lastCaller = msg.sender;
    }
}

contract MacSpoofing {
    address public victim;

    constructor(address _victim) {
        victim = _victim;
    }

    function spoof() external {
        // msg.sender in Victim will be THIS contract, not the attacker
        (bool success, ) = victim.delegatecall(
            abi.encodeWithSignature("sensitiveLogic()")
        );
        require(success, "Delegatecall failed");
    }
}
