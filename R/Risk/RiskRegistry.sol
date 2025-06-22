// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RiskRegistry {
    struct Risk {
        string label;
        uint8 severity;   // 1-10
        uint256 entropy;
        uint256 drift;
    }

    mapping(bytes4 => Risk) public selectorRisk;
    bytes4[] public registered;

    event RiskRegistered(bytes4 indexed selector, string label, uint8 severity);

    function register(bytes4 sel, string calldata label, uint8 severity, uint256 entropy, uint256 drift) external {
        selectorRisk[sel] = Risk(label, severity, entropy, drift);
        if (!_exists(sel)) registered.push(sel);
        emit RiskRegistered(sel, label, severity);
    }

    function score(bytes4 sel) external view returns (uint256) {
        Risk memory r = selectorRisk[sel];
        return uint256(r.severity) * (r.entropy + 1) * (r.drift + 1);
    }

    function _exists(bytes4 sel) internal view returns (bool) {
        for (uint i = 0; i < registered.length; i++) {
            if (registered[i] == sel) return true;
        }
        return false;
    }
}
