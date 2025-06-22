interface IABIReconMutator {
    function getHits() external view returns (ABIReconMutator.ABIHit[] memory);
}

contract ZeroDayAutoReplayer {
    IABIReconMutator public recon;
    address public target;

    event ReplayABI(bytes4 selector, string nameGuess, bool success);

    constructor(address _recon, address _target) {
        recon = IABIReconMutator(_recon);
        target = _target;
    }

    function replayAll() external {
        ABIReconMutator.ABIHit[] memory hits = recon.getHits();
        for (uint256 i = 0; i < hits.length; i++) {
            (bool ok, ) = target.call(abi.encodePacked(hits[i].selector));
            emit ReplayABI(hits[i].selector, hits[i].guessedName, ok);
        }
    }
}
