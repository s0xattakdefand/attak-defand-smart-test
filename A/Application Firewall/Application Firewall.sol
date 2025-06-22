// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApplicationFirewall {
    mapping(bytes4 => bool) public blockedSelectors;
    mapping(address => uint256) public lastCallBlock;
    mapping(address => uint256) public callCount;

    uint256 public entropyThreshold = 12;
    uint256 public maxCallsPerBlock = 3;

    event CallBlocked(address indexed user, bytes4 selector, string reason);
    event CallAllowed(address indexed user, bytes4 selector, uint256 entropy);

    modifier firewall(bytes calldata input) {
        bytes4 selector;
        assembly {
            selector := calldataload(input.offset)
        }

        // Blocked selector check
        if (blockedSelectors[selector]) {
            emit CallBlocked(msg.sender, selector, "Selector is blocked");
            revert("Firewall: Selector blocked");
        }

        // Entropy check
        uint256 entropy = _entropy(input);
        if (entropy < entropyThreshold) {
            emit CallBlocked(msg.sender, selector, "Low entropy input");
            revert("Firewall: Low entropy");
        }

        // Rate limiting
        if (lastCallBlock[msg.sender] == block.number) {
            callCount[msg.sender]++;
            if (callCount[msg.sender] > maxCallsPerBlock) {
                emit CallBlocked(msg.sender, selector, "Rate limit exceeded");
                revert("Firewall: Too many calls");
            }
        } else {
            lastCallBlock[msg.sender] = block.number;
            callCount[msg.sender] = 1;
        }

        emit CallAllowed(msg.sender, selector, entropy);
        _;
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

    function blockSelector(bytes4 sel) external {
        blockedSelectors[sel] = true;
    }

    function allowSelector(bytes4 sel) external {
        blockedSelectors[sel] = false;
    }

    function protectedCall(bytes calldata input) external firewall(input) returns (string memory) {
        return "Call passed firewall.";
    }
}
