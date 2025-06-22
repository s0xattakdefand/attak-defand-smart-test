contract ZeroDayFuzzer {
    event FuzzSent(address target, bytes4 selector);

    function fuzz(address target, uint8 rounds) external {
        for (uint8 i = 0; i < rounds; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(block.timestamp, i, target)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            emit FuzzSent(target, sel);
        }
    }
}
