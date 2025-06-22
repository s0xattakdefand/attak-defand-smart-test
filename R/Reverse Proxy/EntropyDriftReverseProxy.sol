contract DriftProxy {
    address public fuzzHandler;

    constructor(address _fuzzHandler) {
        fuzzHandler = _fuzzHandler;
    }

    fallback() external {
        bytes4 fuzzed = fuzzSelector(msg.sig);
        (bool ok, bytes memory out) = fuzzHandler.delegatecall(
            abi.encodePacked(fuzzed, msg.data[4:])
        );
        require(ok, "Fuzzed call failed");
        assembly { return(add(out, 32), mload(out)) }
    }

    function fuzzSelector(bytes4 sel) public pure returns (bytes4) {
        return bytes4(uint32(sel) ^ 0xdeadbeef); // flip pattern
    }
}
