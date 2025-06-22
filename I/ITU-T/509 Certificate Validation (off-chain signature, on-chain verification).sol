pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract X509CertificateRegistry {
    using ECDSA for bytes32;

    address public certificateAuthority;

    constructor(address _ca) {
        certificateAuthority = _ca;
    }

    event CertificateValidated(address user, string subject);

    function validateCertificate(
        string memory subject,
        uint256 expiry,
        bytes memory signature
    ) external {
        require(block.timestamp < expiry, "Certificate expired");

        bytes32 message = keccak256(abi.encodePacked(msg.sender, subject, expiry));
        bytes32 ethSigned = message.toEthSignedMessageHash();

        require(ethSigned.recover(signature) == certificateAuthority, "Invalid certificate");

        emit CertificateValidated(msg.sender, subject);
    }
}
