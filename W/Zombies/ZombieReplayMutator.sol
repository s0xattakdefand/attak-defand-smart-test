contract ZombieReplayMutator {
    event Mutated(bytes4 selector, address target, bool success);

    function mutateAndReplay(address baseTarget, uint256 rounds) external {
        for (uint256 i = 0; i < rounds; i++) {
            address mutatedTarget = address(uint160(uint256(keccak256(abi.encodePacked(baseTarget, i)))));
            bytes4 selector = bytes4(keccak256(abi.encodePacked(mutatedTarget, block.timestamp, i)));
            (bool ok, ) = mutatedTarget.call(abi.encodePacked(selector));
            emit Mutated(selector, mutatedTarget, ok);
        }
    }
}
