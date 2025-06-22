contract HostedMetaTx {
    address public relayerHost;

    constructor(address _host) {
        relayerHost = _host;
    }

    function executeMetaTx(address user, bytes calldata data, bytes calldata sig) external {
        require(msg.sender == relayerHost, "Not the relayer host");

        // decode data, recover signer from sig, execute on behalf
        // add nonce check, deadline, etc. in production
    }
}
