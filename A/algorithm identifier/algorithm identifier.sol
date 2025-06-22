// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AlgorithmSelector {
    enum Algorithm {
        NONE,
        KECCAK256,
        SHA256,
        RIPEMD160
    }

    mapping(Algorithm => bool) public allowed;
    event AlgorithmUsed(address indexed user, Algorithm algorithm);
    event UnknownAlgorithm(address indexed user, uint256 algorithmId);

    constructor() {
        allowed[Algorithm.KECCAK256] = true;
        allowed[Algorithm.SHA256] = true;
    }

    /// @notice Perform a hash using a selected algorithm
    function computeHash(Algorithm algo, bytes calldata data) external view returns (bytes32) {
        require(allowed[algo], "Algorithm not allowed");

        if (algo == Algorithm.KECCAK256) {
            return keccak256(data);
        } else if (algo == Algorithm.SHA256) {
            return sha256(data);
        } else if (algo == Algorithm.RIPEMD160) {
            return ripemd160Hash(data);
        } else {
            revert("Invalid algorithm");
        }
    }

    /// @notice Restricted algorithm
    function ripemd160Hash(bytes memory data) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(ripemd160(data))));
    }

    /// @notice Register a new algorithm (admin logic could be added)
    function allowAlgorithm(Algorithm algo) external {
        allowed[algo] = true;
    }

    function isAllowed(uint256 algoId) external view returns (bool) {
        if (algoId > uint256(type(Algorithm).max)) {
            return false;
        }
        return allowed[Algorithm(algoId)];
    }
}
