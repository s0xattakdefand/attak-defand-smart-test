interface IRegressionOracle {
    function log(uint8 entropy, uint8 result) external;
}

function fuzzReplay(bytes4 selector) public {
    uint8 entropy = countBits(selector);
    (bool ok, uint256 gasStart) = (false, gasleft());
    (ok, ) = target.call(abi.encodePacked(selector));
    uint256 gasUsed = gasStart - gasleft();
    regressionOracle.log(entropy, ok ? 1 : 0);
}

function countBits(bytes4 s) internal pure returns (uint8 score) {
    uint32 x = uint32(s);
    while (x != 0) { score++; x &= (x - 1); }
}
