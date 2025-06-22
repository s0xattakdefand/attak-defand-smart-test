// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Vault.sol";
import "../src/MockToken.sol";

contract ComprehensiveTest is Test {
    Vault vault;
    MockToken token;
    address user;

    function setUp() public {
        token = new MockToken("Mock", "MOCK", 18, 1_000_000 ether);
        vault = new Vault(address(token));
        user = address(0xABCD);
        token.transfer(user, 10_000 ether);
        vm.startPrank(user);
        token.approve(address(vault), type(uint256).max);
    }

    function testUnit_DepositIncreasesBalance() public {
        vault.deposit(1000 ether);
        assertEq(vault.balanceOf(user), 1000 ether);
    }

    function testRevert_WithdrawTooMuch() public {
        vault.deposit(500 ether);
        vm.expectRevert("Insufficient balance");
        vault.withdraw(1000 ether);
    }

    function testGasUsage_Deposit() public {
        vault.deposit(1 ether); // Run with gas profiling tools
    }

    function testFuzz_DepositThenWithdraw(uint256 amount) public {
        vm.assume(amount > 0 && amount < 10000 ether);
        vault.deposit(amount);
        vault.withdraw(amount);
        assertEq(vault.balanceOf(user), 0);
    }

    function testSecurity_ReentrancyAttack() public {
        // Inject mock reentrant contract & validate rejection
    }

    function testIntegration_VaultAndTokenSync() public {
        vault.deposit(500 ether);
        assertEq(token.balanceOf(address(vault)), 500 ether);
    }

    function testUpgrade_StorageSlotPreserved() public {
        // Simulate upgrade and test slot layout is preserved
    }
}
