// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: the contract is compiled with a set of known addresses 
 * or domain separation for egress. 
 * e.g. we store a static array of known addresses at compile time.
 */
contract HardcodedEgress {
    // Suppose these addresses are known safe protocols
    address constant SAFE1 = 0xAABBCCDDEEFF0011223344556677889900AABBCC;
    address constant SAFE2 = 0xDDCCBBAA99887766554433221100FFEEDDCCAABB;

    event ExternalCall(address indexed target, bool success);

    function callSafe1(bytes calldata data) external {
        (bool success, ) = SAFE1.call(data);
        emit ExternalCall(SAFE1, success);
    }

    function callSafe2(bytes calldata data) external {
        (bool success, ) = SAFE2.call(data);
        emit ExternalCall(SAFE2, success);
    }
}
