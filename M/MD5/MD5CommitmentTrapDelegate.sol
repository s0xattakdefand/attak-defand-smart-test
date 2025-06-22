// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MD5CommitmentTrapDelegate {
    mapping(bytes16 => address) public commitments;
    address public logic;

    constructor(address _logic) {
        logic = _logic;
    }

    function submit(bytes16 hash) external {
        // ❌ Attacker-controlled delegatecall
        (bool ok, ) = logic.delegatecall(
            abi.encodeWithSignature("spoof(bytes16)", hash)
        );
        require(ok, "Delegatecall failed");
    }
}
