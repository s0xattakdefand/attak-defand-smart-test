contract CertificateAuthority {
    address public issuer;
    mapping(bytes32 => bool) public revoked;
    event CertificateIssued(bytes32 certId, address subject, uint256 expiresAt);
    event CertificateRevoked(bytes32 certId);

    constructor(address _issuer) {
        issuer = _issuer;
    }

    function issueCert(address subject, uint256 ttl) external returns (bytes32 certId) {
        require(msg.sender == issuer, "Unauthorized");
        certId = keccak256(abi.encodePacked(subject, block.timestamp));
        emit CertificateIssued(certId, subject, block.timestamp + ttl);
    }

    function revokeCert(bytes32 certId) external {
        require(msg.sender == issuer, "Unauthorized");
        revoked[certId] = true;
        emit CertificateRevoked(certId);
    }

    function isValid(bytes32 certId) external view returns (bool) {
        return !revoked[certId];
    }
}
