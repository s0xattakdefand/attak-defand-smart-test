// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentMethodRegistry - Defines and tracks methods used in protocol assessments

contract AssessmentMethodRegistry {
    address public admin;

    struct Method {
        string name;            // e.g., "StaticAudit", "FuzzSim", "ZKCheck"
        string description;     // Explanation or toolchain used
        string version;         // Tool or procedural version
        bool active;
        uint256 createdAt;
    }

    mapping(string => Method) public methods;
    mapping(bytes32 => string[]) public resultToMethods; // assessment result ID → method names
    string[] public methodNames;

    event MethodRegistered(string name, string version);
    event MethodLinked(bytes32 resultId, string methodName);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerMethod(
        string calldata name,
        string calldata description,
        string calldata version
    ) external onlyAdmin {
        require(methods[name].createdAt == 0, "Method already exists");

        methods[name] = Method({
            name: name,
            description: description,
            version: version,
            active: true,
            createdAt: block.timestamp
        });

        methodNames.push(name);
        emit MethodRegistered(name, version);
    }

    function linkMethodToResult(bytes32 resultId, string calldata methodName) external onlyAdmin {
        require(methods[methodName].active, "Inactive or unknown method");
        resultToMethods[resultId].push(methodName);
        emit MethodLinked(resultId, methodName);
    }

    function getMethodsForResult(bytes32 resultId) external view returns (string[] memory) {
        return resultToMethods[resultId];
    }

    function getAllMethodNames() external view returns (string[] memory) {
        return methodNames;
    }

    function getMethod(string calldata name) external view returns (Method memory) {
        return methods[name];
    }
}
