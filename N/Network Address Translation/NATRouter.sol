// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NATRouter {
    mapping(address => address) public aliasMap; // publicAlias → privateOrigin
    mapping(address => bool) public trustedRelayers;

    modifier onlyRelayer() {
        require(trustedRelayers[msg.sender], "Unauthorized relay");
        _;
    }

    function registerAlias(address publicAlias) external {
        aliasMap[publicAlias] = msg.sender;
    }

    function relay(address publicAlias, address target, bytes calldata payload) external onlyRelayer {
        require(aliasMap[publicAlias] != address(0), "Alias not registered");

        // 🧨 NAT-style masking
        (bool ok, ) = target.call(payload);
        require(ok, "Relay failed");
    }

    function trustRelayer(address relayer, bool status) external {
        trustedRelayers[relayer] = status;
    }
}
