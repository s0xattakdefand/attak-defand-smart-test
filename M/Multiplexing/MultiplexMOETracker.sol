// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MultiplexMOETracker {
    struct SubcallStats {
        uint256 calls;
        uint256 failures;
    }

    mapping(bytes4 => SubcallStats) public stats;

    event SubcallLogged(bytes4 selector, bool success);

    function logSubcall(bytes calldata payload, bool ok) external {
        if (payload.length < 4) return;

        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }

        SubcallStats storage s = stats[selector];
        s.calls++;
        if (!ok) s.failures++;

        emit SubcallLogged(selector, ok);
    }

    function getStats(bytes4 selector) external view returns (uint256, uint256) {
        SubcallStats memory s = stats[selector];
        return (s.calls, s.failures);
    }
}
