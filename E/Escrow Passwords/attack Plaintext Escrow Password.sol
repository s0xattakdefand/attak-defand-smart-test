// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * An escrow where the password is stored on-chain, 
 * or the contract checks a direct equality with a public variable => easy to see or guess.
 */
contract PlaintextEscrowPassword {
    address public seller;
    address public buyer;
    uint256 public price;
    string public escrowPassword; // ❌ Attack: fully visible

    bool public isReleased;

    constructor(address _seller, address _buyer, uint256 _price, string memory _password) payable {
        require(msg.value == _price, "Must fund escrow");
        seller = _seller;
        buyer = _buyer;
        price = _price;
        escrowPassword = _password; // stored in plain sight
        isReleased = false;
    }

    function release(string calldata attempt) external {
        // ❌ Attack: Anyone can see escrowPassword in block explorers
        // and just call release with the same password
        require(keccak256(bytes(attempt)) == keccak256(bytes(escrowPassword)), "Wrong password");
        isReleased = true;
        payable(seller).transfer(price);
    }
}
