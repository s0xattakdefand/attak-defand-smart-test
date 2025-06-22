// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EAPAuthenticator.sol";

contract NaiveEAPMethod is IEAPMethod {
    /**
     * @notice Insecure verification: returns true for any proof.
     */
    function verify(address, bytes calldata) external pure override returns (bool) {
        return true;
    }
}
