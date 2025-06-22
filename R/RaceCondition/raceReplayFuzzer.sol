contract RaceFuzzer {
    event FuzzAttempt(address target, bytes4 selector, bool success);

    function fuzz(address target, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            bytes4 selector = bytes4(keccak256(abi.encodePacked(i, block.timestamp, target)));
            (bool ok, ) = target.call(abi.encodePacked(selector));
            emit FuzzAttempt(target, selector, ok);
        }
    }
}
