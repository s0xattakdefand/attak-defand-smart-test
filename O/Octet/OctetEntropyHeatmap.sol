// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract OctetEntropyHeatmap {
    mapping(bytes4 => uint256[8]) public entropyMap;

    event DriftDetected(bytes4 indexed selector, uint256[8] heat);

    function logSelector(bytes4 selector) external {
        bytes memory b = abi.encodePacked(selector);
        for (uint256 i = 0; i < b.length; i++) {
            entropyMap[selector][i] += uint8(b[i]);
        }
        emit DriftDetected(selector, entropyMap[selector]);
    }

    function getOctetHeat(bytes4 selector, uint8 index) external view returns (uint256) {
        require(index < 4, "Invalid octet index");
        return entropyMap[selector][index];
    }
}
