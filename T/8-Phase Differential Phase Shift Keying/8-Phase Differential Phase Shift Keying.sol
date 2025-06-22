// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EightDPSKAttackDefense - Attack and Defense Simulation for 8-Phase Differential Phase Shift Keying (8-DPSK) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Phase State Machine (No Strict Validation, Vulnerable to Drift and Replay)
contract Insecure8DPSK {
    enum Phase { Phase0, Phase1, Phase2, Phase3, Phase4, Phase5, Phase6, Phase7 }

    Phase public currentPhase;

    event PhaseChanged(Phase indexed fromPhase, Phase indexed toPhase);

    constructor() {
        currentPhase = Phase.Phase0;
    }

    function setPhase(uint8 nextPhase) external {
        require(nextPhase < 8, "Invalid phase");
        emit PhaseChanged(currentPhase, Phase(nextPhase));
        currentPhase = Phase(nextPhase);
    }
}

/// @notice Secure Phase State Machine with Full Phase Validation and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";

contract Secure8DPSK is Ownable {
    enum Phase { Phase0, Phase1, Phase2, Phase3, Phase4, Phase5, Phase6, Phase7 }

    Phase public currentPhase;
    mapping(bytes32 => bool) public usedTransitions;
    uint256 public lastUpdateBlock;

    event PhaseAdvanced(address indexed caller, Phase indexed fromPhase, Phase indexed toPhase, bytes32 transitionId);

    constructor() {
        currentPhase = Phase.Phase0;
        lastUpdateBlock = block.number;
    }

    function advancePhase(uint8 expectedCurrentPhase, uint8 nextPhase, uint256 nonce, bytes calldata signature) external {
        require(expectedCurrentPhase == uint8(currentPhase), "Current phase mismatch");
        require(nextPhase == (expectedCurrentPhase + 1) % 8, "Invalid phase advancement");

        bytes32 transitionHash = keccak256(abi.encodePacked(msg.sender, expectedCurrentPhase, nextPhase, nonce, address(this), block.chainid));
        require(!usedTransitions[transitionHash], "Replay detected");

        address signer = transitionHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        usedTransitions[transitionHash] = true;
        emit PhaseAdvanced(msg.sender, currentPhase, Phase(nextPhase), transitionHash);

        currentPhase = Phase(nextPhase);
        lastUpdateBlock = block.number;
    }

    function currentPhaseInfo() external view returns (Phase phase, uint256 lastUpdatedBlock) {
        return (currentPhase, lastUpdateBlock);
    }
}

/// @notice Attack contract simulating phase drift and replay injection
contract DPSKIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function forcePhase(uint8 phaseId) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("setPhase(uint8)", phaseId)
        );
    }
}
