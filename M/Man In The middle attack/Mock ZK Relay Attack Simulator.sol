// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../zkMetaTx/ZKMetaTxGuarded.sol";

contract MockVerifier {
    function verifyProof(bytes calldata, bytes32) external pure returns (bool) {
        return true; // Always returns valid for simulation
    }
}

contract ZKRelayerProofTest is Test {
    ZKMetaTxGuarded public zkMetaTx;
    MockVerifier public verifier;

    address alice = address(0xA11CE);
    address recipient = address(0xB0B);

    function setUp() public {
        verifier = new MockVerifier();
        zkMetaTx = new ZKMetaTxGuarded(address(verifier));
        vm.deal(address(zkMetaTx), 10 ether);
    }

    function testZKMetaTxRelay() public {
        bytes32 input = keccak256(abi.encodePacked(alice, recipient, 1 ether, 0));
        bytes memory fakeProof = hex"deadbeef"; // mocked
        zkMetaTx.relay(alice, recipient, 1 ether, 0, fakeProof);
        assertEq(recipient.balance, 1 ether);
    }
}
