interface ILoopUplink {
    function pushLoopEvent(address caller, bytes4 selector, uint256 depth) external;
}

contract LoopGuard {
    mapping(bytes32 => uint256) public callDepth;
    ILoopUplink public uplink;

    constructor(address _uplink) {
        uplink = ILoopUplink(_uplink);
    }

    modifier guardLoop(uint256 max) {
        bytes32 sig = keccak256(abi.encodePacked(tx.origin, msg.sender, msg.sig));
        require(callDepth[sig] < max, "🛑 Routing loop blocked");
        callDepth[sig]++;
        uplink.pushLoopEvent(msg.sender, msg.sig, callDepth[sig]);
        _;
        callDepth[sig]--;
    }
}
