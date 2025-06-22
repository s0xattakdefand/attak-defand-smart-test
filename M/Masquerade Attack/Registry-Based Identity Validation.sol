// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title OracleRegistry - Tracks valid oracles by domain hash
contract OracleRegistry {
    mapping(bytes32 => address) public trusted;

    function register(string calldata name, address oracle) external {
        bytes32 id = keccak256(abi.encodePacked(name));
        trusted[id] = oracle;
    }

    function resolve(string calldata name) external view returns (address) {
        return trusted[keccak256(abi.encodePacked(name))];
    }

    function getPrice(string calldata name) external view returns (int256) {
        address oracle = trusted[keccak256(abi.encodePacked(name))];
        require(oracle != address(0), "Not registered");
        (bool ok, bytes memory data) = oracle.staticcall(abi.encodeWithSignature("latestAnswer()"));
        require(ok, "Oracle call failed");
        return abi.decode(data, (int256));
    }
}
