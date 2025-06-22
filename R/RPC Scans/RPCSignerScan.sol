contract RPCSignerScan {
    event PublicSignerDetected(address signer, string origin);

    function report(address signer, string calldata rpcURL) external {
        emit PublicSignerDetected(signer, rpcURL);
    }
}
