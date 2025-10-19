// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableEscrow {
    address public arbiter; // Dispute resolver
    mapping(bytes32 => Escrow) public escrows;

    struct Escrow {
        address buyer;
        address payable seller;
        uint256 amount;
        bool released;
        bool refunded;
    }

    event EscrowCreated(bytes32 indexed escrowId, address buyer, address seller, uint256 amount);
    event FundsReleased(bytes32 indexed escrowId, address to, uint256 amount);
    event FundsRefunded(bytes32 indexed escrowId, address to, uint256 amount);

    constructor() {
        arbiter = msg.sender;
    }

    function createEscrow(bytes32 escrowId, address payable seller) external payable {
        require(msg.value > 0, "Amount must be > 0");
        require(escrows[escrowId].amount == 0, "Escrow ID already exists");
        escrows[escrowId] = Escrow(msg.sender, seller, msg.value, false, false);
        emit EscrowCreated(escrowId, msg.sender, seller, msg.value);
    }

    // Vulnerable: External call before state update (reentrancy risk)
    function releaseFunds(bytes32 escrowId) external {
        Escrow storage escrow = escrows[escrowId];
        require(msg.sender == arbiter || msg.sender == escrow.buyer, "Unauthorized");
        require(escrow.amount > 0, "No funds");
        require(!escrow.released && !escrow.refunded, "Escrow settled");

        (bool success, ) = escrow.seller.call{value: escrow.amount}("");
        require(success, "Transfer failed");

        escrow.released = true;
        emit FundsReleased(escrowId, escrow.seller, escrow.amount);
    }

    function refundFunds(bytes32 escrowId) external {
        Escrow storage escrow = escrows[escrowId];
        require(msg.sender == arbiter, "Only arbiter can refund");
        require(escrow.amount > 0, "No funds");
        require(!escrow.released && !escrow.refunded, "Escrow settled");

        (bool success, ) = escrow.buyer.call{value: escrow.amount}("");
        require(success, "Transfer failed");

        escrow.refunded = true;
        emit FundsRefunded(escrowId, escrow.buyer, escrow.amount);
    }

    function getEscrowBalance(bytes32 escrowId) external view returns (uint256) {
        return escrows[escrowId].amount;
    }
}