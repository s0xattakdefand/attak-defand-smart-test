// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault vault;
    address owner = address(0xB0B);
    address attacker = address(0xBEEF);
    address alice = address(0xA11CE);

    function setUp() public {
        // Deploy Vault from `owner` address
        vm.prank(owner);
        vault = new Vault();
        vm.label(owner, "Owner");
        vm.label(alice, "Alice");
        vm.label(attacker, "Attacker");

        // Fund participants
        vm.deal(alice, 10 ether);
        vm.deal(attacker, 10 ether);
        vm.deal(owner, 1 ether); // ensure owner can receive ETH
    }

    function testDeposit() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        assertEq(vault.balance(alice), 1 ether);
    }

    function testWithdrawSuccess() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.prank(alice);
        vault.withdraw(0.5 ether);
        assertEq(vault.balance(alice), 0.5 ether);
    }

    function testWithdrawFail_TooMuch() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.prank(alice);
        vm.expectRevert("Insufficient balance");
        vault.withdraw(2 ether);
    }

    function testOnlyOwnerCanSweep() public {
        vm.prank(attacker);
        vm.expectRevert("Not owner");
        vault.sweep();
    }

    function testOwnerCanSweep() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        uint256 before = owner.balance;

        vm.prank(owner);
        vault.sweep();

        assertEq(owner.balance, before + 1 ether);
    }
}
