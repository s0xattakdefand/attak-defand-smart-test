// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IZKVerifier {
    function verifyProof(bytes calldata proof, bytes32 signal) external view returns (bool);
}

contract SecurityArchitectureCore {
    address public admin;
    mapping(address => bool) public operators;
    mapping(address => bool) public trustedContracts;
    mapping(address => bool) public paused;

    event OperationExecuted(address indexed caller, string action);
    event TrustedContractAdded(address indexed target);
    event Paused(address indexed target);
    event EmergencyExit(address indexed user, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier onlyTrusted(address target) {
        require(trustedContracts[target], "Target not trusted");
        _;
    }

    modifier notPaused(address target) {
        require(!paused[target], "Target is paused");
        _;
    }

    constructor() {
        admin = msg.sender;
        operators[admin] = true;
    }

    // --- Access Layer ---
    function setOperator(address op, bool status) external onlyAdmin {
        operators[op] = status;
    }

    function setTrustedContract(address target, bool status) external onlyAdmin {
        trustedContracts[target] = status;
        emit TrustedContractAdded(target);
    }

    // --- Execution Layer (ZK-Proof + Operator) ---
    function secureExecute(
        address target,
        bytes calldata payload,
        bytes calldata zkProof,
        bytes32 signal,
        IZKVerifier verifier
    ) external onlyOperator onlyTrusted(target) notPaused(target) {
        require(verifier.verifyProof(zkProof, signal), "ZK invalid");
        (bool success, ) = target.call(payload);
        require(success, "Execution failed");
        emit OperationExecuted(msg.sender, "secureExecute");
    }

    // --- Emergency Layer ---
    function pauseTarget(address target) external onlyAdmin {
        paused[target] = true;
        emit Paused(target);
    }

    function emergencyExit(address payable user) external onlyAdmin {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds");
        user.transfer(balance);
        emit EmergencyExit(user, balance);
    }

    receive() external payable {}
}
