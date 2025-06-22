// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AIScorer {
    struct Attack {
        bytes4 selector;
        uint256 gasUsed;
        uint8 entropy;
        uint256 fails;
        uint256 blockLogged;
    }

    mapping(bytes4 => Attack) public log;

    function logAttack(bytes4 selector, uint256 gasUsed, uint8 entropy, bool success) external {
        Attack storage a = log[selector];
        a.selector = selector;
        a.gasUsed = gasUsed;
        a.entropy = entropy;
        if (!success) a.fails++;
        a.blockLogged = block.number;
    }

    function score(bytes4 selector) public view returns (uint256) {
        Attack memory a = log[selector];
        if (a.entropy == 0 || a.gasUsed == 0) return 0;
        uint256 driftFactor = a.entropy * a.gasUsed;
        return a.fails > 0 ? driftFactor / a.fails : driftFactor;
    }
}
