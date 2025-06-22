// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract OptimizedAllocator {
    mapping(address => uint256) public allocations;
    address[] public recipients;

    /// @notice Unoptimized loop (writes repeatedly, redundant length checks)
    function benchmarkSimple(uint256 baseAmount) external {
        for (uint i = 0; i < recipients.length; i++) {
            allocations[recipients[i]] += baseAmount * (i + 1); // unnecessary computation
        }
    }

    /// @notice Optimized version using memory and caching
    function benchmarkOptimized(uint256 baseAmount) external {
        address[] memory localRecipients = recipients;
        uint256 len = localRecipients.length;

        for (uint256 i = 0; i < len; ++i) {
            unchecked {
                allocations[localRecipients[i]] += baseAmount * (i + 1); // inside unchecked to save gas
            }
        }
    }

    /// @notice Add recipients in batch
    function addRecipients(address[] calldata users) external {
        for (uint256 i = 0; i < users.length; i++) {
            recipients.push(users[i]);
        }
    }

    /// @notice Optimized read (batch)
    function getAllocations(address[] calldata users) external view returns (uint256[] memory result) {
        uint256 len = users.length;
        result = new uint256[](len);
        for (uint256 i = 0; i < len; ++i) {
            result[i] = allocations[users[i]];
        }
    }
}
