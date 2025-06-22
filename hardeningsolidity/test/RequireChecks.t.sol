// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/RequireChecks.sol";

contract RequireChecksTest is Test {
    RequireChecks rc;
    address donor = address(0xBEEF);

    function setUp() public {
        rc = new RequireChecks();
        vm.deal(donor, 10 ether); // Provide donor with ETH
    }

    function testRejectSmallDonation() public {
        vm.prank(donor);
        vm.expectRevert("Donation too small");
        rc.donate{value: 0.005 ether}();
    }

    function testAcceptValidDonation() public {
        vm.prank(donor);
        rc.donate{value: 0.05 ether}();
        assertEq(rc.donations(donor), 0.05 ether);
        assertEq(rc.totalReceived(), 0.05 ether);
    }

    function testRejectAfterGoalReached() public {
        vm.prank(donor);
        rc.donate{value: 1 ether}(); // Fill goal

        vm.prank(donor);
        vm.expectRevert("Goal reached");
        rc.donate{value: 0.1 ether}();
    }

    function testWithdrawByOwnerOnly() public {
        // Donor fills the goal
        vm.prank(donor);
        rc.donate{value: 1 ether}();

        // Donor tries to withdraw — must fail
        vm.expectRevert("Not owner");
        vm.prank(donor);
        rc.withdraw();

        // Owner withdraws — must succeed
        vm.prank(address(this)); // The contract deployer is the owner
        rc.withdraw();

        // Check contract balance is empty
        assertEq(address(rc).balance, 0);
    }
}
