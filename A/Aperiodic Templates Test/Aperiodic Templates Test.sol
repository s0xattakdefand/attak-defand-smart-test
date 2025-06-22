// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AperiodicTemplateScanner {
    event TemplatePatternDetected(address indexed sender, bytes template, uint256 count);
    event CleanInput(address indexed sender);

    uint256 public templateSize = 3; // Size of aperiodic template in bytes
    uint256 public threshold = 3;    // Repetition threshold

    function scan(bytes calldata input) external returns (bool passed) {
        uint256 len = input.length;
        require(len >= templateSize, "Input too short");

        mapping(bytes32 => uint256) storage counts;
        bytes32[] memory templates = new bytes32[](len - templateSize + 1);
        uint256 detected = 0;

        for (uint i = 0; i <= len - templateSize; i++) {
            bytes memory slice = new bytes(templateSize);
            for (uint j = 0; j < templateSize; j++) {
                slice[j] = input[i + j];
            }
            bytes32 hash = keccak256(slice);
            bool found = false;

            for (uint k = 0; k < detected; k++) {
                if (templates[k] == hash) {
                    counts[hash]++;
                    if (counts[hash] >= threshold) {
                        emit TemplatePatternDetected(msg.sender, slice, counts[hash]);
                        return false;
                    }
                    found = true;
                    break;
                }
            }

            if (!found) {
                templates[detected] = hash;
                counts[hash] = 1;
                detected++;
            }
        }

        emit CleanInput(msg.sender);
        return true;
    }
}
