contract FallbackSelfDestruct {
    address payable public owner;

    constructor() {
        owner = payable(msg.sender);
    }

    fallback() external {
        if (msg.sig == bytes4(keccak256("terminate()"))) {
            selfdestruct(owner);
        }
    }
}
