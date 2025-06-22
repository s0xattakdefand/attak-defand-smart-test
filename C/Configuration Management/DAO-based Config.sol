// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Other Type:
 * A simplified approach where param changes require 
 * a DAO / governance vote. 
 * (Pseudocode as actual DAO logic is extensive.)
 */
contract DAOManagedConfig {
    uint256 public param;
    address public dao;

    constructor(address _dao) {
        dao = _dao;
    }

    function setParam(uint256 newVal) external {
        // require a check that a DAO vote occurred or 
        // any governance call from the DAO
        require(msg.sender == dao, "Not authorized");
        param = newVal;
    }
}
