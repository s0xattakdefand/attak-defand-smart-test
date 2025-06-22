contract AutoSimExecutor {
    event SimResult(address user, bytes32 commitHash, string reveal, bool match);

    function simulateCommitReveal(address target, string calldata revealVal) external {
        bytes32 computed = keccak256(abi.encodePacked(revealVal));
        (bool ok, ) = target.call(abi.encodeWithSignature("reveal(string)", revealVal));
        emit SimResult(msg.sender, computed, revealVal, ok);
    }
}
