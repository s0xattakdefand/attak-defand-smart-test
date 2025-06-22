contract MetaTxHeaderRouter {
    struct MetaTxHeader {
        address user;
        uint256 nonce;
        bytes data;
    }

    mapping(address => uint256) public nonces;

    function execute(MetaTxHeader calldata header) external {
        require(header.nonce == nonces[header.user], "Invalid nonce");
        nonces[header.user]++;
        (bool ok, ) = address(this).call(header.data); // Caution: Validate `data` safety
        require(ok, "Execution failed");
    }
}
