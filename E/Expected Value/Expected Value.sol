// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExpectedValueAttackDefense - Full Attack and Defense Simulation for Expected Value Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Lottery (Vulnerable to Expected Value Exploits)
contract InsecureLottery {
    mapping(address => uint256) public balances;
    address[] public players;

    function join() external payable {
        require(msg.value == 0.01 ether, "Must send 0.01 ETH");
        players.push(msg.sender);
    }

    function drawWinner() external {
        require(players.length >= 2, "Not enough players");

        uint256 winnerIndex = uint256(blockhash(block.number - 1)) % players.length;
        address winner = players[winnerIndex];

        balances[winner] += address(this).balance;
        delete players;
    }

    function claim() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to claim");
        balances[msg.sender] = 0;
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    receive() external payable {}
}

/// @notice Secure Lottery with Strong Expected Value Protection
contract SecureLottery {
    address public admin;
    address[] public players;
    uint256 public ticketPrice = 0.01 ether;
    uint256 public commitBlock;
    bytes32 public commitHash;
    bool public committed;
    bool public revealed;

    event Committed(bytes32 hash, uint256 blockNumber);
    event Revealed(uint256 randomNumber, address winner);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    function join() external payable {
        require(msg.value == ticketPrice, "Incorrect ticket price");
        require(committed, "Lottery not started");
        players.push(msg.sender);
    }

    function commitRandomness(bytes32 hash) external onlyAdmin {
        require(!committed, "Already committed");
        commitHash = hash;
        commitBlock = block.number;
        committed = true;

        emit Committed(hash, block.number);
    }

    function revealRandomness(uint256 secret) external onlyAdmin {
        require(committed, "No commit yet");
        require(!revealed, "Already revealed");
        require(keccak256(abi.encodePacked(secret)) == commitHash, "Invalid secret");

        uint256 randomNumber = uint256(keccak256(abi.encodePacked(secret, blockhash(commitBlock)))) % players.length;
        address winner = players[randomNumber];

        (bool sent, ) = winner.call{value: address(this).balance}("");
        require(sent, "Transfer to winner failed");

        revealed = true;

        emit Revealed(randomNumber, winner);
    }

    receive() external payable {}
}

/// @notice Attack contract trying to manipulate expected lottery outcomes
contract ExpectedValueIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function predictableJoin() external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: 0.01 ether}(
            abi.encodeWithSignature("join()")
        );
    }
}
