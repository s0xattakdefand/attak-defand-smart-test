// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RadiationMonitor {
    mapping(bytes4 => uint256) public selectorHits;
    mapping(address => uint256) public exposureScore;
    uint256 public threshold = 3;

    event RadiationDetected(address target, bytes4 selector, uint256 score);
    event HotZone(address indexed target, uint256 score);

    function log(bytes4 selector, address origin) external {
        selectorHits[selector]++;
        exposureScore[origin] += _entropyScore(selector);

        emit RadiationDetected(origin, selector, exposureScore[origin]);

        if (exposureScore[origin] > threshold) {
            emit HotZone(origin, exposureScore[origin]);
        }
    }

    function _entropyScore(bytes4 selector) internal pure returns (uint8) {
        uint8 score;
        uint32 x = uint32(selector);
        for (; x > 0; score++) {
            x &= x - 1; // hamming weight
        }
        return score;
    }
}
