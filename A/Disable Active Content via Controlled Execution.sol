// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TrustedLibrary {
    uint256 public data;

    function updateData(uint256 newData) public {
        data = newData;
    }
}

contract SafeActiveContent {
    address public owner;
    address public trustedLib;

    constructor(address _trustedLib) {
        owner = msg.sender;
        trustedLib = _trustedLib;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    // Only owner can trigger limited, known-safe delegatecalls
    function safeExecute(bytes calldata payload) public onlyOwner {
        require(_isValidFunction(payload), "Unsafe function");

        (bool success, ) = trustedLib.delegatecall(payload);
        require(success, "Delegatecall failed");
    }

    function _isValidFunction(bytes calldata data) internal pure returns (bool) {
        // Only allow updateData(uint256) function call
        bytes4 sig = bytes4(data[:4]);
        return sig == bytes4(keccak256("updateData(uint256)"));
    }
}
