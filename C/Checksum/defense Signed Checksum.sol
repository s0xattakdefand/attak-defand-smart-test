// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
/**
 * This contract ensures that the checksum was authorized by a signer.
 */
contract VerifiedChecksum {
    using ECDSA for bytes32;

    address public trustedSigner;
    bytes32 public officialChecksum;
    
    constructor(address signer) {
        trustedSigner = signer;
    }

    event ChecksumUpdated(bytes32 indexed newChecksum);

    function updateChecksum(bytes32 newChecksum, bytes calldata sig) external {
        msgHash = newChecksum.toEthSignedMessageHash();
        address recovered = msgHash.recover(sig);
        require(recovered == trustedSigner, "Invalid signature");

        officialChecksum = newChecksum;
        emit ChecksumUpdated(newChecksum);
    }

    function verifyData(bytes memory data) external view returns (bool) {
        return (keccak256(data) == officialChecksum);
    }
}