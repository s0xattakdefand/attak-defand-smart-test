// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../ransomware/BalanceBasedRansom.sol";

contract RansomFuzzer is Test {
    BalanceBasedRansom ransom;

    function setUp() public {
        ransom = new BalanceBasedRansom(address(this), address(this));
    }

    function balanceOf(address) external pure returns (uint256) {
        return 10 ether;
    }

    function testFuzzPayRansom(uint256 sent) public {
        ransom.updateRequired();
        if (sent >= ransom.required()) {
            ransom.payRansom{value: sent}();
            assertTrue(ransom.paid());
        }
    }

    receive() external payable {}
}
