// Safe Price Bounds in DeFi Vault

function deposit(uint256 amount, uint256 maxAcceptablePrice) external {
    uint256 currentPrice = getPriceFromOracle();
    require(currentPrice <= maxAcceptablePrice, "Slippage too high");
    // Safe: user protects against front-run price spike
}

// time gated voting 
function vote(uint256 proposalId) external {
    require(block.timestamp >= proposalStart[proposalId], "Voting not started");
    require(block.timestamp <= proposalEnd[proposalId], "Voting closed");
    // Safe time comparisons for access gating
}

// zk proof commitment comparisons
mapping(bytes32 => bool) public validProofs;

function submitProof(bytes calldata input, bytes calldata proof) external {
    bytes32 hash = keccak256(abi.encodePacked(input, proof));
    require(validProofs[hash], "Invalid ZK proof");
    // Safe: Only approved precomputed hashes accepted
}

