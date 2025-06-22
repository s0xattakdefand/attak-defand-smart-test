// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiTamperVault {
    address public admin;
    bytes32 public configHash;
    string public configData;
    bool public isTampered;

    event ConfigSet(bytes32 indexed hash, string data);
    event TamperDetected(address indexed actor, string attemptedData);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor(string memory initialConfig) {
        admin = msg.sender;
        configData = initialConfig;
        configHash = keccak256(abi.encodePacked(initialConfig));
        emit ConfigSet(configHash, initialConfig);
    }

    function updateConfig(string calldata newConfig) external onlyAdmin {
        bytes32 newHash = keccak256(abi.encodePacked(newConfig));

        if (newHash == configHash) {
            revert("No changes detected");
        }

        if (!_isAuthorizedChange(newConfig)) {
            isTampered = true;
            emit TamperDetected(msg.sender, newConfig);
            revert("Tamper attempt detected");
        }

        configData = newConfig;
        configHash = newHash;
        emit ConfigSet(configHash, newConfig);
    }

    function _isAuthorizedChange(string memory input) internal pure returns (bool) {
        // For demo: only allow config updates that start with "safe:"
        bytes memory b = bytes(input);
        if (b.length < 5) return false;
        return (b[0] == "s" && b[1] == "a" && b[2] == "f" && b[3] == "e" && b[4] == ":");
    }

    function verifyIntegrity() external view returns (bool) {
        return !isTampered && keccak256(abi.encodePacked(configData)) == configHash;
    }
}
