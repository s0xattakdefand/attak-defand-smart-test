pragma solidity ^0.8.21;

contract AntiLegionNFT {
    uint256 public constant MAX_PER_WALLET = 1;
    mapping(address => uint256) public minted;

    modifier noContract() {
        require(tx.origin == msg.sender, "No contract bots");
        _;
    }

    function mint() external payable noContract {
        require(minted[msg.sender] < MAX_PER_WALLET, "Mint limit");
        minted[msg.sender]++;
        // Mint logic
    }
}
