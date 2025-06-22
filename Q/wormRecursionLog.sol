// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract QAZReinfectionTracker {
    mapping(address => uint256) public infectionCount;
    mapping(address => bytes4[]) public selectorHistory;

    event Reinfection(address indexed target, bytes4 selector, uint256 count);

    function logInfection(address target, bytes4 sel) external {
        infectionCount[target]++;
        selectorHistory[target].push(sel);
        emit Reinfection(target, sel, infectionCount[target]);
    }

    function getHistory(address target) external view returns (bytes4[] memory) {
        return selectorHistory[target];
    }
}
