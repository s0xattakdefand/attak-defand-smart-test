// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ZombieSelectorHeatmap {
    struct Hit {
        uint256 count;
        uint256 lastBlock;
    }

    mapping(bytes4 => Hit) public selectorHits;
    bytes4[] public allTracked;

    event SelectorLogged(bytes4 indexed selector, uint256 count);

    function log(bytes4 selector) external {
        if (selectorHits[selector].count == 0) {
            allTracked.push(selector);
        }
        selectorHits[selector].count++;
        selectorHits[selector].lastBlock = block.number;
        emit SelectorLogged(selector, selectorHits[selector].count);
    }

    function getAllTracked() external view returns (bytes4[] memory) {
        return allTracked;
    }

    function getEntropyDensity(bytes4 selector) external view returns (uint256) {
        return selectorHits[selector].count;
    }
}
