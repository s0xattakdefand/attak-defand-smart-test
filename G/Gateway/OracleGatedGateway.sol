// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getStatus(address user) external view returns (bool);
}

contract OracleGatedGateway {
    IOracle public oracle;

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    function gateway(address to, bytes calldata data) external {
        require(oracle.getStatus(msg.sender), "Oracle blocked");
        (bool success, ) = to.call(data);
        require(success, "Forward failed");
    }
}
