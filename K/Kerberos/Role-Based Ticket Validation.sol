pragma solidity ^0.8.21;

contract KerberosRoleAuth {
    using ECDSA for bytes32;

    enum Role { USER, ADMIN }
    address public kdc;

    constructor(address _kdc) {
        kdc = _kdc;
    }

    function accessService(
        address user,
        Role role,
        string memory serviceName,
        uint256 expiresAt,
        bytes memory signature
    ) external {
        require(block.timestamp <= expiresAt, "Expired ticket");

        bytes32 digest = keccak256(abi.encodePacked(user, role, serviceName, expiresAt));
        address signer = digest.toEthSignedMessageHash().recover(signature);

        require(signer == kdc, "Invalid signature");

        if (role == Role.ADMIN) {
            // Admin-only function
        } else {
            // General user function
        }
    }
}
