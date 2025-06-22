// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObligationAttackDefense - Attack and Defense Simulation for Obligations in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Obligation Management (No Fulfillment Verification, No Penalty Enforcement)
contract InsecureObligationContract {
    struct Obligation {
        address obligor;
        uint256 amount;
        bool fulfilled;
    }

    mapping(uint256 => Obligation) public obligations;
    uint256 public nextId;

    event ObligationCreated(uint256 indexed id, address indexed obligor, uint256 amount);
    event ObligationFulfilled(uint256 indexed id, address indexed obligor);

    function createObligation(uint256 amount) external {
        obligations[nextId] = Obligation(msg.sender, amount, false);
        emit ObligationCreated(nextId, msg.sender, amount);
        nextId++;
    }

    function fulfillObligation(uint256 id) external {
        Obligation storage o = obligations[id];
        require(o.obligor == msg.sender, "Not your obligation");
        o.fulfilled = true; // 🔥 No payment or action verification!
        emit ObligationFulfilled(id, msg.sender);
    }
}

/// @notice Secure Obligation Contract (Full Fulfillment and Penalty Enforcement)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObligationContract is Ownable {
    struct Obligation {
        address obligor;
        uint256 amount;
        uint256 deadline;
        bool fulfilled;
        bool penalized;
    }

    mapping(uint256 => Obligation) private obligations;
    uint256 private nextId;
    uint256 public constant PENALTY_RATE = 10; // 10%

    event ObligationCreated(uint256 indexed id, address indexed obligor, uint256 amount, uint256 deadline);
    event ObligationFulfilled(uint256 indexed id, address indexed obligor);
    event ObligationPenalized(uint256 indexed id, address indexed obligor, uint256 penaltyAmount);

    function createObligation(uint256 amount, uint256 duration) external {
        require(amount > 0, "Invalid amount");
        obligations[nextId] = Obligation({
            obligor: msg.sender,
            amount: amount,
            deadline: block.timestamp + duration,
            fulfilled: false,
            penalized: false
        });

        emit ObligationCreated(nextId, msg.sender, amount, block.timestamp + duration);
        nextId++;
    }

    function fulfillObligation(uint256 id) external payable {
        Obligation storage o = obligations[id];
        require(o.obligor == msg.sender, "Not your obligation");
        require(!o.fulfilled, "Already fulfilled");
        require(block.timestamp <= o.deadline, "Deadline passed");
        require(msg.value == o.amount, "Incorrect amount sent");

        o.fulfilled = true;
        emit ObligationFulfilled(id, msg.sender);
    }

    function penalizeOverdueObligation(uint256 id) external onlyOwner {
        Obligation storage o = obligations[id];
        require(!o.fulfilled, "Already fulfilled");
        require(!o.penalized, "Already penalized");
        require(block.timestamp > o.deadline, "Not overdue yet");

        o.penalized = true;
        uint256 penaltyAmount = (o.amount * PENALTY_RATE) / 100;

        // Collect penalty (could be recorded, minted, or distributed)
        emit ObligationPenalized(id, o.obligor, penaltyAmount);
    }

    function getObligation(uint256 id) external view returns (address obligor, uint256 amount, uint256 deadline, bool fulfilled, bool penalized) {
        Obligation memory o = obligations[id];
        return (o.obligor, o.amount, o.deadline, o.fulfilled, o.penalized);
    }
}

/// @notice Attack contract simulating obligation evasion
contract ObligationIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeFulfill(uint256 id) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("fulfillObligation(uint256)", id)
        );
    }
}
