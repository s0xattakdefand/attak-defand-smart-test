// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title Simple Linear Regression Oracle
contract RegressionOracle {
    uint256 public sumX;
    uint256 public sumY;
    uint256 public sumXY;
    uint256 public sumX2;
    uint256 public count;

    event DataLogged(uint256 x, uint256 y);

    function log(uint256 x, uint256 y) external {
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumX2 += x * x;
        count += 1;
        emit DataLogged(x, y);
    }

    /// Predict Y for a new X using simple linear regression: y = a*x + b
    function predict(uint256 x) external view returns (int256 y) {
        if (count < 2) return 0;
        int256 n = int256(count);
        int256 a_num = int256(n * sumXY - sumX * sumY);
        int256 a_den = int256(n * sumX2 - sumX * sumX);
        if (a_den == 0) return 0;
        int256 a = a_num * 1e18 / a_den;
        int256 b = (int256(sumY) * 1e18 - a * int256(sumX)) / int256(n);
        y = (a * int256(x) + b) / 1e18;
    }
}
