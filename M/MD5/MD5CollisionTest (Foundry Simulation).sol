// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../../src/md5/MD5CollisionTrap.sol";

contract MD5CollisionTest is Test {
    MD5CollisionTrap public trap;

    function setUp() public {
        trap = new MD5CollisionTrap();
    }

    function testCollisionBypass() public {
        bytes16 collisionHash = 0xd41d8cd98f00b204e9800998ecf8427e; // example MD5 for empty string
        trap.submit(collisionHash);
        vm.expectRevert("Already used");
        trap.submit(collisionHash); // replay or second collision
    }
}
