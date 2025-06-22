// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * A secure approach: multiple node addresses (like a mini p2p network) 
 * must sign data => no single node can compromise the result.
 */
contract MultiNodeConsensus {
    using ECDSA for bytes32;

    mapping(address => bool) public knownNodes; // multiple addresses
    uint256 public requiredNodes;
    uint256 public data;

    constructor(address[] memory nodes, uint256 _required) {
        for (uint256 i = 0; i < nodes.length; i++) {
            knownNodes[nodes[i]] = true;
        }
        requiredNodes = _required;
    }

    function updateData(uint256 newVal, bytes[] calldata sigs, address[] calldata signers) external {
        require(sigs.length == signers.length, "Mismatch");
        bytes32 messageHash = keccak256(abi.encodePacked(newVal, address(this)))
            .toEthSignedMessageHash();

        uint256 validCount = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            if (knownNodes[signers[i]]) {
                address recovered = messageHash.recover(sigs[i]);
                if (recovered == signers[i]) {
                    validCount++;
                }
            }
        }
        require(validCount >= requiredNodes, "Not enough node signatures");
        data = newVal;
    }
}
