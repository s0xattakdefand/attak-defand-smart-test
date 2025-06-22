// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ErfcApprox {
    uint256 constant ONE = 1e18;
    uint256 constant SQRT_PI_INV = 5641895835e9; // ≈ 2 / sqrt(pi) × 1e18

    function erfc(uint256 x) external pure returns (uint256) {
        require(x < 6e18, "x too large for approximation");

        // Use rational approximation for erfc(x)
        // Approximate: erfc(x) ≈ exp(-x^2) * (a + b*x + c*x^2 + d*x^3)
        // Constants chosen for [0,6] domain
        uint256 a = 1e18;             // 1.0
        uint256 b = 0.278393e18;
        uint256 c = 0.230389e18;
        uint256 d = 0.000972e18;
        uint256 e = 0.078108e18;

        uint256 x2 = (x * x) / ONE;

        uint256 denom = ONE +
            (b * x) / ONE +
            (c * x2) / ONE +
            (d * x2 * x) / ONE / ONE +
            (e * x2 * x2) / ONE / ONE;

        uint256 expNegX2 = expNeg(x2); // e^-x^2 approximation

        return (expNegX2 * ONE) / denom;
    }

    // Approximate e^-x using a 3-term series: e^-x ≈ 1 - x + x^2/2 (for small x)
    function expNeg(uint256 x) internal pure returns (uint256) {
        uint256 term1 = ONE;
        uint256 term2 = x;
        uint256 term3 = (x * x) / (2 * ONE);
        return term1 - term2 + term3;
    }
}
