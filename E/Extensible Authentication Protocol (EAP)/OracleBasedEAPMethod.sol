// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EAPAuthenticator.sol";

interface IOracle {
    function getAuthStatus(address user) external view returns (bool);
}

contract OracleBasedEAPMethod is IEAPMethod {
    IOracle public oracle;

    constructor(address oracleAddr) {
        oracle = IOracle(oracleAddr);
    }

    /**
     * @notice Delegates authentication decision to an external oracle.
     */
    function verify(address user, bytes calldata) external view override returns (bool) {
        return oracle.getAuthStatus(user);
    }
}
