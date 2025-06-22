// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DomainParameterValidator - Verifies known safe domain parameters used in Web3 cryptography

contract DomainParameterValidator {
    address public admin;

    enum ParamType { ECDSA_Curve, HashFunction, ZKFieldModulus, MerkleRoot, BLSGenerator }

    struct DomainParam {
        bytes32 id;
        ParamType paramType;
        bytes value;          // Raw bytes: curve ID, modulus, G1 point, etc.
        string label;
        bool valid;
        uint256 timestamp;
    }

    mapping(bytes32 => DomainParam) public parameters;
    bytes32[] public paramIds;

    event DomainParamAdded(bytes32 indexed id, ParamType paramType, string label);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDomainParam(
        ParamType paramType,
        bytes calldata value,
        string calldata label
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(paramType, value));
        parameters[id] = DomainParam({
            id: id,
            paramType: paramType,
            value: value,
            label: label,
            valid: true,
            timestamp: block.timestamp
        });
        paramIds.push(id);
        emit DomainParamAdded(id, paramType, label);
        return id;
    }

    function isParamValid(bytes32 id) external view returns (bool) {
        return parameters[id].valid;
    }

    function getParam(bytes32 id) external view returns (DomainParam memory) {
        return parameters[id];
    }

    function getAllParams() external view returns (bytes32[] memory) {
        return paramIds;
    }
}
