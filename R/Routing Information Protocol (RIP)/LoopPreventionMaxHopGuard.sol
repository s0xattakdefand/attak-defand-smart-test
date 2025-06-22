contract MaxHopGuard {
    uint8 public constant MAX_HOPS = 15;
    mapping(bytes32 => uint8) public hopTracker;

    modifier noExcessiveHop(bytes4 selector) {
        bytes32 sig = keccak256(abi.encodePacked(tx.origin, msg.sender, selector));
        require(hopTracker[sig] < MAX_HOPS, "🛑 RIP loop detected");
        hopTracker[sig]++;
        _;
        hopTracker[sig]--;
    }
}
