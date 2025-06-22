// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IGatewayTarget {
    function handle(bytes calldata payload) external returns (bool);
}

contract ApplicationLevelGateway {
    mapping(bytes4 => bool) public allowedSelectors;
    IGatewayTarget public targetContract;
    uint256 public entropyThreshold = 10;

    event GatewayAllowed(address indexed user, bytes4 selector, uint256 entropy);
    event GatewayBlocked(address indexed user, bytes4 selector, string reason);

    constructor(address _target) {
        targetContract = IGatewayTarget(_target);
    }

    modifier gatewayFilter(bytes calldata input) {
        bytes4 selector;
        assembly {
            selector := calldataload(input.offset)
        }

        if (!allowedSelectors[selector]) {
            emit GatewayBlocked(msg.sender, selector, "Selector not allowed");
            revert("ALG: Blocked selector");
        }

        uint256 entropy = _entropy(input);
        if (entropy < entropyThreshold) {
            emit GatewayBlocked(msg.sender, selector, "Low entropy");
            revert("ALG: Low entropy payload");
        }

        emit GatewayAllowed(msg.sender, selector, entropy);
        _;
    }

    function forward(bytes calldata input) external gatewayFilter(input) returns (bool) {
        return targetContract.handle(input);
    }

    function allowSelector(bytes4 sel) external {
        allowedSelectors[sel] = true;
    }

    function blockSelector(bytes4 sel) external {
        allowedSelectors[sel] = false;
    }

    function _entropy(bytes memory data) internal pure returns (uint256 score) {
        bool[256] memory seen;
        for (uint i = 0; i < data.length; i++) {
            seen[uint8(data[i])] = true;
        }
        for (uint i = 0; i < 256; i++) {
            if (seen[i]) score++;
        }
    }
}
