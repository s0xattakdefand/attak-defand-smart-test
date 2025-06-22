// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../../src/nat/NATRouter.sol";

contract NATPoisonEntropyTest is Test {
    NATRouter public router;
    address[] public attackers;

    function setUp() public {
        router = new NATRouter();
        for (uint256 i = 0; i < 5; i++) {
            address aliasAddr = address(uint160(uint256(keccak256(abi.encodePacked("alias", i)))));
            vm.prank(address(uint160(i+1)));
            router.registerAlias(aliasAddr);
            attackers.push(aliasAddr);
        }
    }

    function testEntropySpread() public {
        uint256 base = uint160(attackers[0]);
        for (uint256 i = 1; i < attackers.length; i++) {
            uint160 drift = uint160(attackers[i]) ^ base;
            uint256 spread = countBits(drift);
            console.log("Drift bits between alias 0 and", i, "=", spread);
            assertTrue(spread > 0);
        }
    }

    function countBits(uint256 x) internal pure returns (uint256 count) {
        while (x > 0) {
            count += x & 1;
            x >>= 1;
        }
    }
}
