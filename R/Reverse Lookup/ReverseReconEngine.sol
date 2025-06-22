// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ReverseReconEngine {
    struct ABIEntry {
        string name;
        uint8 entropy;
        uint256 drift;
    }

    struct AddressMeta {
        string name;
        string role;
        string tag;
    }

    struct BytecodeEntry {
        string label;
    }

    struct HashRole {
        string label;
    }

    mapping(bytes4 => ABIEntry) public abiSelectors;
    mapping(address => AddressMeta) public addressLabels;
    mapping(bytes32 => BytecodeEntry) public bytecodeMap;
    mapping(bytes32 => HashRole) public hashRoles;

    bytes4[] public trackedSelectors;

    // === REGISTER ===

    function registerABI(bytes4 selector, string calldata name, uint8 entropy, uint256 drift) external {
        abiSelectors[selector] = ABIEntry(name, entropy, drift);
        if (!isTracked(selector)) trackedSelectors.push(selector);
    }

    function registerAddress(address who, string calldata name, string calldata role, string calldata tag) external {
        addressLabels[who] = AddressMeta(name, role, tag);
    }

    function registerBytecode(bytes32 hash, string calldata label) external {
        bytecodeMap[hash] = BytecodeEntry(label);
    }

    function registerPreimage(bytes32 hash, string calldata label) external {
        hashRoles[hash] = HashRole(label);
    }

    // === RESOLVE ===

    function resolveSelector(bytes4 sel) external view returns (ABIEntry memory) {
        return abiSelectors[sel];
    }

    function resolveAddress(address who) external view returns (AddressMeta memory) {
        return addressLabels[who];
    }

    function resolveBytecode(address contractAddr) external view returns (string memory) {
        return bytecodeMap[keccak256(contractAddr.code)].label;
    }

    function resolveHash(bytes32 h) external view returns (string memory) {
        return hashRoles[h].label;
    }

    function getTopVolatileSelector() external view returns (bytes4 selector) {
        uint256 maxScore = 0;
        for (uint i = 0; i < trackedSelectors.length; i++) {
            ABIEntry memory e = abiSelectors[trackedSelectors[i]];
            uint256 score = e.entropy * (e.drift + 1);
            if (score > maxScore) {
                selector = trackedSelectors[i];
                maxScore = score;
            }
        }
    }

    function isTracked(bytes4 sel) internal view returns (bool exists) {
        for (uint i = 0; i < trackedSelectors.length; i++) {
            if (trackedSelectors[i] == sel) return true;
        }
    }
}
