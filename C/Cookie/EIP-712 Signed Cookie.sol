// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * Cookie Type 4 (Other/Defense):
 * - Off-chain cookie with an EIP-712 signature
 * - Contract stores or verifies a signature, not the cookie data
 */
contract SignedCookie {
    using ECDSA for bytes32;

    // Optional reference storing user => last verified signature
    mapping(address => bytes) public lastSig;

    address public trustedSigner; // e.g., your backend

    constructor(address signer) {
        trustedSigner = signer;
    }

    /**
     * @dev Called by user to register a signed cookie from the trusted signer.
     * signature covers (user, cookieString, nonce, address(this))
     */
    function registerCookie(
        string calldata cookieData,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // Recreate the message hashed with domain
        bytes32 hashMsg = keccak256(
            abi.encodePacked(msg.sender, cookieData, nonce, address(this))
        ).toEthSignedMessageHash();

        address recovered = hashMsg.recover(signature);
        require(recovered == trustedSigner, "Invalid signer for cookie");

        // Store the signature or mark user as validated
        lastSig[msg.sender] = signature;
    }

    /**
     * @dev Optional read function to see if user has a valid signature.
     */
    function hasValidCookie(address user) external view returns (bool) {
        return (lastSig[user].length != 0);
    }
}
