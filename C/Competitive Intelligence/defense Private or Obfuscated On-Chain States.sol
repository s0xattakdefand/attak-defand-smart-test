// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense scenario:
 * - We store user deposit data in a hashed or partial format, 
 *   so direct competitor scraping is harder.
 * - Real usage might do advanced off-chain encryption or ephemeral storage.
 */
contract ObfuscatedDeposits {
    // Instead of storing raw deposit amounts, store hashed or partial data
    mapping(address => bytes32) public depositHash;

    // Admin or aggregator can reconstruct real amounts off-chain, 
    // or user reveals only when needed
    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    /**
     * @dev User sets deposit info as a hash to obscure actual deposit from public scrapers.
     */
    function setDepositHash(bytes32 hashedData) external {
        depositHash[msg.sender] = hashedData;
    }

    /**
     * @dev Admin can read full deposit amounts if user reveals off-chain
     * or in a private environment, preventing naive competitor scraping.
     */
    function verifyOffChain(address user, bytes32 secretSalt, uint256 depositAmount)
        external view returns (bool)
    {
        require(msg.sender == admin, "Only admin can verify");
        bytes32 check = keccak256(abi.encodePacked(user, depositAmount, secretSalt));
        return (check == depositHash[user]);
    }
}
