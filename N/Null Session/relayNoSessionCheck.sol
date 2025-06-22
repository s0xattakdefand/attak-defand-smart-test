contract RelayNoSessionCheck {
    function relay(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data); // ❌ No signer or msgSender validation
        require(ok, "Relay failed");
    }
}
