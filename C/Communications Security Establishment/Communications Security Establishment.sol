// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CSEAuthority {
    address public rootAdmin;

    enum KeyType { Signer, Verifier, Relayer }

    struct TrustedKey {
        KeyType keyType;
        address keyAddress;
        string label;
        bool active;
        uint256 registeredAt;
    }

    mapping(address => TrustedKey) public trustedKeys;
    address[] public allKeys;

    event KeyRegistered(address indexed key, KeyType keyType, string label);
    event KeyDeactivated(address indexed key);
    event VerifiedCommunication(address indexed from, string action);

    modifier onlyAdmin() {
        require(msg.sender == rootAdmin, "CSE: Not root");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
    }

    function registerKey(address key, KeyType keyType, string calldata label) external onlyAdmin {
        require(trustedKeys[key].registeredAt == 0, "CSE: Already registered");

        trustedKeys[key] = TrustedKey({
            keyType: keyType,
            keyAddress: key,
            label: label,
            active: true,
            registeredAt: block.timestamp
        });

        allKeys.push(key);
        emit KeyRegistered(key, keyType, label);
    }

    function deactivateKey(address key) external onlyAdmin {
        require(trustedKeys[key].active, "CSE: Already inactive");
        trustedKeys[key].active = false;
        emit KeyDeactivated(key);
    }

    function isTrusted(address key, KeyType expected) external view returns (bool) {
        return trustedKeys[key].active && trustedKeys[key].keyType == expected;
    }

    function logVerifiedCommunication(address from, string calldata action) external onlyAdmin {
        emit VerifiedCommunication(from, action);
    }

    function getAllKeys() external view returns (address[] memory) {
        return allKeys;
    }

    function getKey(address addr) external view returns (
        KeyType keyType,
        string memory label,
        bool active,
        uint256 registeredAt
    ) {
        TrustedKey memory k = trustedKeys[addr];
        return (k.keyType, k.label, k.active, k.registeredAt);
    }
}
