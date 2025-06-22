// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ASICActivityDefender {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callFrequency;
    uint256 public maxCallsPerBlock = 3;
    uint256 public minEntropy = 12;

    event CallBlocked(address indexed sender, string reason);
    event CallPassed(address indexed sender, uint256 entropy);

    modifier antiASIC(bytes calldata input) {
        // Rate limiting (per block)
        if (lastBlock[msg.sender] == block.number) {
            callFrequency[msg.sender]++;
            if (callFrequency[msg.sender] > maxCallsPerBlock) {
                emit CallBlocked(msg.sender, "Too many calls");
                revert("ASIC behavior blocked: call rate");
            }
        } else {
            callFrequency[msg.sender] = 1;
            lastBlock[msg.sender] = block.number;
        }

        // Entropy detection
        uint256 score = _entropy(input);
        if (score < minEntropy) {
            emit CallBlocked(msg.sender, "Low entropy input");
            revert("ASIC behavior blocked: entropy");
        }

        emit CallPassed(msg.sender, score);
        _;
    }

    function protectedCall(bytes calldata input) external antiASIC(input) returns (string memory) {
        return "Execution passed ASIC filter.";
    }

    function _entropy(bytes memory data) internal pure returns (uint256 uniqueBytes) {
        bool[256] memory seen;
        for (uint i = 0; i < data.length; i++) {
            seen[uint8(data[i])] = true;
        }
        for (uint i = 0; i < 256; i++) {
            if (seen[i]) uniqueBytes++;
        }
    }
}
