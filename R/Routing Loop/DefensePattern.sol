contract RoutingLoopGuard {
    mapping(bytes32 => uint256) public callCount;

    modifier noLoop(uint256 maxDepth) {
        bytes32 sig = keccak256(abi.encodePacked(tx.origin, msg.sender, msg.sig));
        require(callCount[sig] < maxDepth, "Routing loop detected");
        callCount[sig]++;
        _;
        callCount[sig]--;
    }
}
