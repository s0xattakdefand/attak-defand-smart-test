// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * We store only a hash of the password, not the plaintext.
 * The escrow is funded, and only the user who knows the real password can reveal it.
 * Attackers cannot see the real password in the contract, just the hash.
 */
contract HashedEscrowPassword {
    address public seller;
    address public buyer;
    uint256 public price;

    // Only the hash of the password is stored => no direct plaintext
    bytes32 public hashedPassword;

    bool public isReleased;

    constructor(address _seller, address _buyer, uint256 _price, bytes32 _hashedPassword) payable {
        require(msg.value == _price, "Must fund escrow");
        seller = _seller;
        buyer = _buyer;
        price = _price;
        hashedPassword = _hashedPassword;
        isReleased = false;
    }

    /**
     * @dev The user reveals the plaintext + salt. We check if keccak256(plaintext+salt) == hashedPassword.
     */
    function release(string calldata plaintext, bytes32 salt) external {
        require(!isReleased, "Already released");

        // Recreate the hash
        bytes32 check = keccak256(abi.encodePacked(plaintext, salt));
        require(check == hashedPassword, "Wrong password or salt");

        isReleased = true;
        payable(seller).transfer(price);
    }
}
