// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title LoopbackHoneypot - Detects attacker calling fallback via self
contract LoopbackHoneypot {
    event FallbackCalled(address indexed caller, uint256 gasLeft);

    fallback() external payable {
        require(msg.sender != address(this), "Loopback attempt detected");
        emit FallbackCalled(msg.sender, gasleft());
    }

    function simulateAttack() external {
        address(this).call(abi.encodeWithSignature("unknown()")); // will hit fallback
    }

    receive() external payable {}
}
