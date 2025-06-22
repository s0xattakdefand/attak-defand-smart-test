struct ABIProfile {
    string name;
    uint8 entropy;
    uint256 success;
    uint256 total;
}

mapping(bytes4 => ABIProfile) public abiMap;

function label(bytes4 selector, string calldata name, uint8 entropy, bool ok) external {
    ABIProfile storage p = abiMap[selector];
    p.name = name;
    p.entropy = entropy;
    p.total++;
    if (ok) p.success++;
}

function abiScore(bytes4 selector) external view returns (uint256 score) {
    ABIProfile memory p = abiMap[selector];
    if (p.total == 0) return 0;
    uint256 rate = (p.success * 1e4) / p.total;
    score = uint256(p.entropy) * rate;
}
