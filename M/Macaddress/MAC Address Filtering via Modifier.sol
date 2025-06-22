// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MACFilter {
    address[] public allowed;

    modifier onlyAllowed() {
        bool ok;
        for (uint i = 0; i < allowed.length; i++) {
            if (msg.sender == allowed[i]) {
                ok = true;
                break;
            }
        }
        require(ok, "Not allowed");
        _;
    }

    function setAllowed(address[] calldata addrs) external {
        delete allowed;
        for (uint i = 0; i < addrs.length; i++) {
            allowed.push(addrs[i]);
        }
    }

    function secureFunction() external onlyAllowed {
        // Protected logic
    }
}
