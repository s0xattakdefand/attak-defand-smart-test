// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MultiPartyEscrow {
    // Possibly you do a hashed password + 2-of-3 multi-sig approach
    // This snippet shows partial timelock fallback.

    address public seller;
    address public buyer;
    uint256 public price;
    uint256 public deadline;

    constructor(address _seller, address _buyer, uint256 _price, uint256 _deadline) payable {
        require(msg.value == _price, "Must fund");
        seller = _seller;
        buyer = _buyer;
        price = _price;
        deadline = _deadline;
    }

    function releaseToSeller() external {
        // e.g. require password or some multi-sig, or if time passes => fallback
        require(block.timestamp > deadline, "Wait or do password method");
        payable(seller).transfer(price);
    }
}
