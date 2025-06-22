contract zkErrorBound {
    ErfcApprox public erfc;

    constructor(address _erfc) {
        erfc = ErfcApprox(_erfc);
    }

    function soundnessError(uint256 challengeStdDevs) external view returns (uint256) {
        // Probability that a dishonest prover escapes detection
        // Tail bound using erfc(x): soundness error ≈ 0.5 * erfc(x / sqrt(2))
        uint256 x = (challengeStdDevs * 707106781e9) / 1e18; // divide by sqrt(2)
        uint256 erfcVal = erfc.erfc(x);
        return erfcVal / 2;
    }
}
