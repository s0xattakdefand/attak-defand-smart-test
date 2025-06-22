// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MonocultureDetector - Scans deployed contracts for codehash duplication
contract MonocultureDetector {
    function detect(address[] calldata targets) external view returns (bool isMonoculture, bytes32 sharedHash) {
        if (targets.length == 0) return (false, 0);

        sharedHash = getCodeHash(targets[0]);

        for (uint256 i = 1; i < targets.length; i++) {
            if (getCodeHash(targets[i]) != sharedHash) {
                return (false, 0);
            }
        }

        return (true, sharedHash);
    }

    function getCodeHash(address target) public view returns (bytes32 hash) {
        assembly {
            hash := extcodehash(target)
        }
    }
}
