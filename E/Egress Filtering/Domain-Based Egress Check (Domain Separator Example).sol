// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach:
 * We do a domain check or signature from a recognized domain or aggregator, 
 * so even if the user sets the 'target', we verify a signature from a domain-based key 
 * that ensures the call is legitimate.
 */
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DomainBasedEgress {
    using ECDSA for bytes32;

    address public domainSigner;

    event ExternalCall(address indexed target, bool success);

    constructor(address signer) {
        domainSigner = signer;
    }

    function callExternal(
        address target, 
        bytes calldata data, 
        bytes calldata signature
    ) external {
        // We verify the domain-based signature -> legit call
        bytes32 msgHash = keccak256(abi.encodePacked(target, data, address(this)))
            .toEthSignedMessageHash();
        address recovered = msgHash.recover(signature);
        require(recovered == domainSigner, "Invalid domain signature");

        (bool success, ) = target.call(data);
        emit ExternalCall(target, success);
    }
}
