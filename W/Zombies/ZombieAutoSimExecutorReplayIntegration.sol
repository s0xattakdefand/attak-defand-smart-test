function replayZombieEntropy(address baseTarget, uint8 rounds) external {
    for (uint8 i = 0; i < rounds; i++) {
        address guess = address(uint160(uint(keccak256(abi.encodePacked(baseTarget, i)))));
        bytes4 sel = bytes4(keccak256(abi.encodePacked(guess, i, block.timestamp)));
        (bool ok, ) = guess.call(abi.encodePacked(sel));
        emit Replayed(sel, guess, ok);
        if (ok) {
            uplink.logThreat(sel, "ZombieSelectorReplay", "Successful zombie reactivation");
        }
    }
}
