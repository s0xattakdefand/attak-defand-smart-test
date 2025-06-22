contract ProxySpoofAttack {
    function spoof(address victim, bytes calldata payload) external {
        (bool ok, ) = victim.call(payload); // 🚨 impersonates proxy caller
        require(ok, "Spoof failed");
    }
}
