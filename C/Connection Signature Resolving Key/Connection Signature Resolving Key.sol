// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureKeyRegistry {
    using ECDSA for bytes32;

    address public admin;
    mapping(bytes32 => address) public resolvingKeys; // e.g., domainHash => signer address

    event KeyRegistered(bytes32 indexed domain, address signer);
    event SignatureVerified(bytes32 indexed domain, address signer, bytes32 msgHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerKey(bytes32 domain, address signer) external onlyAdmin {
        resolvingKeys[domain] = signer;
        emit KeyRegistered(domain, signer);
    }

    function verify(bytes32 domain, bytes32 messageHash, bytes calldata signature) external view returns (bool) {
        address expected = resolvingKeys[domain];
        address recovered = messageHash.toEthSignedMessageHash().recover(signature);
        return recovered == expected;
    }

    function verifyStrict(bytes32 domain, bytes32 messageHash, bytes calldata signature) external returns (bool) {
        address expected = resolvingKeys[domain];
        address recovered = messageHash.toEthSignedMessageHash().recover(signature);
        require(recovered == expected, "Invalid signature");
        emit SignatureVerified(domain, recovered, messageHash);
        return true;
    }
}
