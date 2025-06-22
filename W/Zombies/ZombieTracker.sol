// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ZombieTracker {
    mapping(address => bool) public isZombie;
    address[] public zombies;

    event ZombieFound(address zombie);
    event ZombieRemoved(address target);

    function report(address target) external {
        require(!isZombie[target], "Already tracked");
        isZombie[target] = true;
        zombies.push(target);
        emit ZombieFound(target);
    }

    function purge(address target) external {
        require(isZombie[target], "Not tracked");
        isZombie[target] = false;
        emit ZombieRemoved(target);
    }

    function list() external view returns (address[] memory) {
        return zombies;
    }
}
