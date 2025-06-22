contract SpoofedRelay {
    function relayToTarget(address target, bytes calldata data) external {
        // Looks like a legitimate HTTPS relay but no signature/proof
        (bool ok, ) = target.call(data); // 🚨 No auth, could exploit
        require(ok, "Call failed");
    }
}
