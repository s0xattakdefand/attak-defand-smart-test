event Drift(bytes4 selector, string guess, string status);

function replayAll() external {
    ABIReconMutator.ABIHit[] memory hits = recon.getHits();
    for (uint256 i = 0; i < hits.length; i++) {
        (bool ok, ) = target.call(abi.encodePacked(hits[i].selector));
        string memory status = ok ? "hit" : "dead code drift";
        emit Drift(hits[i].selector, hits[i].guessedName, status);
    }
}
