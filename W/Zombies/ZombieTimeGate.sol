// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ZombieTimeGate {
    uint256 public immutable activationStart;
    uint256 public immutable activationEnd;
    address public target;
    bytes4 public selector;

    event ZombieTriggered(address indexed target, bytes4 selector, bool success);

    constructor(address _target, bytes4 _selector, uint256 start, uint256 end) {
        require(start < end, "Invalid window");
        activationStart = start;
        activationEnd = end;
        target = _target;
        selector = _selector;
    }

    function trigger() external {
        require(block.timestamp >= activationStart, "Too early");
        require(block.timestamp <= activationEnd, "Too late");

        (bool ok, ) = target.call(abi.encodePacked(selector));
        emit ZombieTriggered(target, selector, ok);
    }
}
