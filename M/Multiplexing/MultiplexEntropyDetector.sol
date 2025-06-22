// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MultiplexEntropyDetector {
    event EntropyScore(bytes4 selector, uint256 count);

    mapping(bytes4 => uint256) public selectorCounts;

    function track(bytes calldata payload) external {
        if (payload.length < 4) return;
        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }
        selectorCounts[selector]++;
        emit EntropyScore(selector, selectorCounts[selector]);
    }

    function entropyEstimate(bytes4[] calldata sel) external view returns (uint256 entropy) {
        uint256 sum = 0;
        for (uint256 i = 0; i < sel.length; i++) {
            sum += selectorCounts[sel[i]];
        }
        for (uint256 i = 0; i < sel.length; i++) {
            uint256 c = selectorCounts[sel[i]];
            if (c > 0) {
                uint256 ratio = (c * 1e18) / sum;
                entropy += (ratio * log2(ratio)) / 1e18;
            }
        }
        entropy = 0 - entropy; // invert to get positive Shannon entropy
    }

    function log2(uint256 x) internal pure returns (uint256) {
        return x > 0 ? (logBase(x, 2)) : 0;
    }

    function logBase(uint256 x, uint256 base) internal pure returns (uint256) {
        uint256 result = 0;
        while (x >= base) {
            result++;
            x /= base;
        }
        return result * 1e18; // normalize
    }
}
