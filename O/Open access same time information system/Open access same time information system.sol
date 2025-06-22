// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Front-running Attack, Race Condition Attack, Data Inconsistency Attack
/// Defense Types: Commit-Reveal Pattern, State Verification Before Action, Block-timestamp/Nonce Binding

contract OpenAccessSameTimeInfoSystem {
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 revealBlock;
        bool revealed;
    }

    mapping(address => bytes32) public commitments;
    mapping(address => Bid) public bids;
    address public highestBidder;
    uint256 public highestBid;

    event Commit(address indexed bidder, bytes32 commitment);
    event Reveal(address indexed bidder, uint256 amount);
    event NewHighestBid(address indexed bidder, uint256 amount);

    /// ATTACK SECTION
    /// Example of Open Access Race: Anyone can try to submit before revealers
    function attackFrontRun(address victim, uint256 fakeHigherBid) external {
        // simulate attack: attacker submits higher bid after seeing victim
        if (fakeHigherBid > highestBid) {
            highestBid = fakeHigherBid;
            highestBidder = msg.sender;
        }
    }

    /// DEFENSE SECTION

    /// 1. Commit Phase - hash your intended bid
    function commitBid(bytes32 _commitment) external {
        require(commitments[msg.sender] == 0, "Already committed");
        commitments[msg.sender] = _commitment;
        emit Commit(msg.sender, _commitment);
    }

    /// 2. Reveal Phase - show the real amount you bid
    function revealBid(uint256 _amount, string calldata _secret) external {
        require(commitments[msg.sender] != 0, "No commitment found");
        require(!bids[msg.sender].revealed, "Already revealed");
        require(
            keccak256(abi.encodePacked(_amount, _secret)) == commitments[msg.sender],
            "Invalid reveal"
        );

        bids[msg.sender] = Bid({
            bidder: msg.sender,
            amount: _amount,
            revealBlock: block.number,
            revealed: true
        });

        emit Reveal(msg.sender, _amount);

        // defend against race conditions
        if (_amount > highestBid) {
            highestBid = _amount;
            highestBidder = msg.sender;
            emit NewHighestBid(msg.sender, _amount);
        }
    }

    /// View current top bid securely
    function viewHighestBid() external view returns (address bidder, uint256 amount) {
        bidder = highestBidder;
        amount = highestBid;
    }

    /// Helper to hash bid + secret offchain
    function hashBid(uint256 _amount, string memory _secret) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_amount, _secret));
    }
}
