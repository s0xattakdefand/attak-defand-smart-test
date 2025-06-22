// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract LoopbackReentrancy {
    uint256 public balance;
    bool private locked;

    constructor() payable {
        balance = msg.value;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        require(!locked, "Reentrant detected");
        locked = true;

        if (balance >= 1 ether) {
            // 👿 Loopback call to self
            (bool success, ) = address(this).call(abi.encodeWithSignature("withdraw()"));
            require(success, "Loopback failed");

            balance -= 1 ether;
            payable(msg.sender).transfer(1 ether);
        }

        locked = false;
    }

    receive() external payable {}
}
