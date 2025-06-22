contract CrossChainIngress {
    address public trustedRelayer;

    constructor(address relayer) {
        trustedRelayer = relayer;
    }

    modifier onlyRelayer() {
        require(msg.sender == trustedRelayer, "Invalid relayer");
        _;
    }

    function processMessage(bytes calldata data) external onlyRelayer {
        // Process only if relayed by trusted source
    }
}
