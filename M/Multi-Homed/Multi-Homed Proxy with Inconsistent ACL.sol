// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MultiHomedProxy {
    address public owner;
    address public backendA;
    address public backendB;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _a, address _b) {
        owner = msg.sender;
        backendA = _a;
        backendB = _b;
    }

    function route(bool useA, bytes calldata data) external {
        address target = useA ? backendA : backendB;

        // 💥 No auth check on backendB = exploit path
        (bool ok, ) = target.call(data);
        require(ok, "Call failed");
    }

    function updateB(address newB) external onlyOwner {
        backendB = newB;
    }
}
