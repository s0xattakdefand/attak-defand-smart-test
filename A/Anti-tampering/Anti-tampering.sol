// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiTamperingGuard {
    address public immutable admin;
    bytes32 public immutable deploymentHash;

    string public systemConfig;
    bytes32 public configHash;
    bool public tampered;

    event ConfigSet(string newConfig, bytes32 configHash);
    event TamperDetected(string attemptedData, address indexed actor);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(string memory initConfig) {
        admin = msg.sender;
        systemConfig = initConfig;
        configHash = keccak256(abi.encodePacked(initConfig));
        deploymentHash = keccak256(abi.encodePacked(address(this), block.chainid, block.timestamp, initConfig));
        emit ConfigSet(initConfig, configHash);
    }

    function updateConfig(string calldata newConfig) external onlyAdmin {
        bytes32 newHash = keccak256(abi.encodePacked(newConfig));

        // Tamper detection: config must start with approved prefix
        if (!_isValidPrefix(newConfig)) {
            tampered = true;
            emit TamperDetected(newConfig, msg.sender);
            revert("Tamper attempt detected");
        }

        systemConfig = newConfig;
        configHash = newHash;
        emit ConfigSet(newConfig, newHash);
    }

    function verifyIntegrity() external view returns (bool) {
        return !tampered && keccak256(abi.encodePacked(systemConfig)) == configHash;
    }

    function _isValidPrefix(string memory str) internal pure returns (bool) {
        bytes memory b = bytes(str);
        if (b.length < 6) return false;
        return (b[0] == "s" && b[1] == "a" && b[2] == "f" && b[3] == "e" && b[4] == ":" && b[5] == "-");
    }
}
