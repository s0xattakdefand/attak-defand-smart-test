contract HostBoundPermit {
    using ECDSA for bytes32;
    mapping(address => uint256) public nonces;

    event Executed(address user, address host);

    function execute(
        address user,
        address host,
        bytes calldata data,
        bytes calldata sig
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(user, host, data, nonces[user])).toEthSignedMessageHash();
        require(hash.recover(sig) == user, "Invalid signature");
        nonces[user]++;
        emit Executed(user, host);
    }
}
