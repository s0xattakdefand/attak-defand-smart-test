// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ADSMonitor {
    event SuspectedADS(address indexed sender, bytes4 selector, uint256 calldataLength, bytes trailingData);
    event FallbackADS(address indexed sender, bytes data);
    event ReceiveADS(address indexed sender, uint256 value);

    fallback() external payable {
        emit FallbackADS(msg.sender, msg.data);

        if (msg.data.length > 4) {
            bytes4 selector;
            assembly {
                selector := calldataload(0)
            }

            bytes memory trailing;
            if (msg.data.length > 4) {
                trailing = sliceTrailingData(msg.data);
            }

            emit SuspectedADS(msg.sender, selector, msg.data.length, trailing);
        }
    }

    receive() external payable {
        emit ReceiveADS(msg.sender, msg.value);
    }

    function sliceTrailingData(bytes calldata input) internal pure returns (bytes memory) {
        if (input.length <= 4) return "";
        bytes memory trailing = new bytes(input.length - 4);
        for (uint256 i = 4; i < input.length; i++) {
            trailing[i - 4] = input[i];
        }
        return trailing;
    }
}
