// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Access Control Rule Logic Circuit Simulation (ACRLCS)
contract ACRLogicCircuitSim {
    address public admin;

    enum LogicGate { NONE, INPUT, AND, OR, XOR, NOT }

    struct CircuitNode {
        LogicGate gate;
        uint256[] inputs; // input node IDs
        address roleAddr; // only used for INPUT gate
    }

    mapping(uint256 => CircuitNode) public circuit;     // nodeId → logic gate
    mapping(address => bool) public roleFlags;          // simulate role assignments
    uint256 public rootNodeId;

    event GateEvaluated(uint256 nodeId, LogicGate gate, bool result);
    event AttackDetected(address attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setRoleFlag(address user, bool val) external onlyAdmin {
        roleFlags[user] = val;
    }

    function setNode(
        uint256 nodeId,
        LogicGate gate,
        uint256[] calldata inputs,
        address roleAddr
    ) external onlyAdmin {
        circuit[nodeId] = CircuitNode(gate, inputs, roleAddr);
    }

    function setRoot(uint256 nodeId) external onlyAdmin {
        rootNodeId = nodeId;
    }

    function evaluateCircuit() external view returns (bool) {
        return _evaluate(rootNodeId);
    }

    function _evaluate(uint256 nodeId) internal view returns (bool) {
        CircuitNode memory node = circuit[nodeId];
        bool result;

        if (node.gate == LogicGate.INPUT) {
            result = roleFlags[node.roleAddr];
        } else if (node.gate == LogicGate.AND) {
            result = true;
            for (uint i = 0; i < node.inputs.length; i++) {
                result = result && _evaluate(node.inputs[i]);
            }
        } else if (node.gate == LogicGate.OR) {
            result = false;
            for (uint i = 0; i < node.inputs.length; i++) {
                result = result || _evaluate(node.inputs[i]);
            }
        } else if (node.gate == LogicGate.XOR) {
            result = false;
            for (uint i = 0; i < node.inputs.length; i++) {
                result = result != _evaluate(node.inputs[i]);
            }
        } else if (node.gate == LogicGate.NOT) {
            require(node.inputs.length == 1, "NOT gate must have one input");
            result = !_evaluate(node.inputs[0]);
        } else {
            revert("Invalid gate");
        }

        return result;
    }

    function accessControlledAction() external {
        bool allowed = _evaluate(rootNodeId);
        emit GateEvaluated(rootNodeId, circuit[rootNodeId].gate, allowed);

        if (!allowed) {
            emit AttackDetected(msg.sender, "Logic circuit blocked access");
            revert("Access denied by logic circuit");
        }

        // 🚀 Protected logic here
    }
}
