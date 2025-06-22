// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AuthenticNameVerifier {
    using ECDSA for bytes32;

    address public trustedSigner;
    string public verifiedName;

    event NameVerified(address indexed user, string name);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    function verifyName(string calldata name, uint256 nonce, bytes calldata signature) public {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, name, nonce));
        bytes32 ethSigned = hash.toEthSignedMessageHash();

        address recovered = ethSigned.recover(signature);
        require(recovered == trustedSigner, "Invalid signer");

        verifiedName = name;
        emit NameVerified(msg.sender, name);
    }
}
