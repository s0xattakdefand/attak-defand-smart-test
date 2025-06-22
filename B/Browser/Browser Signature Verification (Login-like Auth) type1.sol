contract BrowserSigVerifier {
    using ECDSA for bytes32;

    address public backend;

    constructor(address _backend) {
        backend = _backend;
    }

    function verifyLogin(bytes32 msgHash, bytes calldata signature) public view returns (bool) {
        return msgHash.toEthSignedMessageHash().recover(signature) == backend;
    }
}
