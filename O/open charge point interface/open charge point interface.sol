// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Free-Rider Abuse, Replay Attack, Fake Activation Attack
/// Defense Types: Payment Enforcement Before Activation, Nonce/Timestamp Binding, Whitelisted User Registration

contract OpenChargePointInterface {
    uint256 public pricePerCharge = 0.01 ether;
    address public owner;

    mapping(address => bool) public whitelist;
    mapping(bytes32 => bool) public usedHashes; // prevent replay
    mapping(address => uint256) public chargesCompleted;

    event Charged(address indexed user, uint256 amount);
    event Whitelisted(address indexed user);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // DEFENSE: Only whitelisted users can interact
    function whitelistUser(address _user) external onlyOwner {
        whitelist[_user] = true;
        emit Whitelisted(_user);
    }

    // ATTACK Simulation: open-access charge function
    function attackFreeRide() external {
        // attacker tries to abuse charging without payment
        chargesCompleted[msg.sender]++;
        emit Charged(msg.sender, 0); // no payment
    }

    /// DEFENSE: Proper charge point interface
    function charge(bytes32 _hash, uint8 v, bytes32 r, bytes32 s) external payable {
        require(whitelist[msg.sender], "Not whitelisted");
        require(msg.value >= pricePerCharge, "Insufficient payment");

        // verify hash freshness
        require(!usedHashes[_hash], "Replay detected");

        // reconstruct signed message
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(msg.sender, block.number)))
        );

        address signer = ecrecover(prefixedHash, v, r, s);
        require(signer == msg.sender, "Invalid signature");

        // Mark this action as used
        usedHashes[_hash] = true;

        chargesCompleted[msg.sender]++;

        emit Charged(msg.sender, msg.value);
    }

    // Owner withdraws funds
    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // Helper to generate the hash offchain
    function generateHash(address _user, uint256 _blockNumber) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_user, _blockNumber));
    }
}
