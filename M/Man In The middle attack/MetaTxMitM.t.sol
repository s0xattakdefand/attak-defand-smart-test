// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../src/MetaTxMitM.sol";

contract MetaTxMitMTest is Test {
    MetaTxMitM public exploit;
    address alice;
    address bob;
    uint256 aliceKey;

    function setUp() public {
        exploit = new MetaTxMitM();
        (alice, aliceKey) = makeAddrAndKey("Alice");
        bob = makeAddr("Bob");
        vm.deal(alice, 10 ether);
        vm.deal(address(exploit), 10 ether);
    }

    function testReplayAttack() public {
        uint256 value = 1 ether;
        uint256 nonce = 1;

        bytes32 hash = keccak256(abi.encodePacked(alice, bob, value, nonce));
        bytes memory sig = vm.sign(aliceKey, hash.toEthSignedMessageHash());

        // Attacker replays same meta tx twice
        exploit.relayMetaTx(alice, bob, value, nonce, sig);
        vm.expectRevert("Already used");
        exploit.relayMetaTx(alice, bob, value, nonce, sig);
    }
}
