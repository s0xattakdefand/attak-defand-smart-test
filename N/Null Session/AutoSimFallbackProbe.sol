contract AutoSimFallbackProbe {
    function fuzzFallback(address target) external {
        for (uint256 i = 0; i < 10; i++) {
            bytes memory drift = abi.encodePacked(bytes4(keccak256(abi.encodePacked(i))));
            (bool ok, ) = target.call(drift);
            emit FallbackFuzz(target, drift, ok);
        }
    }

    event FallbackFuzz(address indexed target, bytes data, bool success);
}
