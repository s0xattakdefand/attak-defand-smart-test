// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract OnChainAntivirus {
    mapping(bytes4 => bool) public blockedSelectors;
    mapping(address => bool) public flaggedAddresses;

    uint256 public entropyThreshold = 16; // lower entropy = higher risk
    uint256 public maxCallsPerBlock = 10;

    mapping(address => uint256) public callsThisBlock;

    event BlockedCall(address indexed sender, bytes4 selector, string reason);
    event Flagged(address indexed attacker);

    constructor() {
        // Example malicious selectors
        blockedSelectors[bytes4(keccak256("selfdestruct()"))] = true;
        blockedSelectors[bytes4(keccak256("delegatecall(address,bytes)"))] = true;
    }

    modifier antivirus(bytes calldata data) {
        // 1. Selector check
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        if (blockedSelectors[selector]) {
            flaggedAddresses[msg.sender] = true;
            emit BlockedCall(msg.sender, selector, "Malicious selector");
            revert("Blocked by Antivirus");
        }

        // 2. Call rate limiting
        if (block.number == lastBlock[msg.sender]) {
            callsThisBlock[msg.sender]++;
        } else {
            callsThisBlock[msg.sender] = 1;
            lastBlock[msg.sender] = block.number;
        }

        if (callsThisBlock[msg.sender] > maxCallsPerBlock) {
            flaggedAddresses[msg.sender] = true;
            emit BlockedCall(msg.sender, selector, "Call rate exceeded");
            revert("Blocked by Antivirus: rate");
        }

        // 3. Entropy check
        if (_entropyScore(data) < entropyThreshold) {
            flaggedAddresses[msg.sender] = true;
            emit BlockedCall(msg.sender, selector, "Low entropy payload");
            revert("Blocked by Antivirus: entropy");
        }

        _;
    }

    mapping(address => uint256) public lastBlock;

    function _entropyScore(bytes memory data) internal pure returns (uint256 score) {
        bool[256] memory seen;
        for (uint i = 0; i < data.length; i++) {
            seen[uint8(data[i])] = true;
        }
        for (uint i = 0; i < 256; i++) {
            if (seen[i]) score++;
        }
    }

    function scan(bytes calldata data) external antivirus(data) returns (string memory) {
        return "Payload is clean";
    }

    function isFlagged(address user) external view returns (bool) {
        return flaggedAddresses[user];
    }

    function addBlockedSelector(bytes4 sel) external {
        blockedSelectors[sel] = true;
    }

    function removeBlockedSelector(bytes4 sel) external {
        blockedSelectors[sel] = false;
    }
}
