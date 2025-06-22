// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntropyAuthenticationAttackDefense - Attack and Defense Simulation for Entropy Authentication in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Entropy Authentication (Predictable Challenge, No Expiry)
contract InsecureEntropyAuth {
    mapping(address => uint256) public lastChallenge;

    event ChallengeIssued(address indexed challenger, uint256 challenge);
    event Authenticated(address indexed challenger);

    function issueChallenge() external {
        uint256 challenge = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
        lastChallenge[msg.sender] = challenge;
        emit ChallengeIssued(msg.sender, challenge);
    }

    function authenticate(uint256 guess) external {
        require(lastChallenge[msg.sender] == guess, "Invalid guess");
        emit Authenticated(msg.sender);
    }
}

/// @notice Secure Entropy Authentication with Expiry, Nonce, and Hardened Entropy
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureEntropyAuth is Ownable {
    struct Challenge {
        uint256 value;
        uint256 expiresAt;
    }

    mapping(address => Challenge) public activeChallenges;
    uint256 public constant CHALLENGE_TTL = 5 minutes;

    event ChallengeIssued(address indexed challenger, uint256 challenge, uint256 expiresAt);
    event Authenticated(address indexed challenger);

    function issueChallenge() external {
        uint256 challenge = uint256(
            keccak256(
                abi.encodePacked(
                    block.prevrandao, // Unpredictable source after London fork
                    block.timestamp,
                    msg.sender,
                    address(this)
                )
            )
        );

        activeChallenges[msg.sender] = Challenge({
            value: challenge,
            expiresAt: block.timestamp + CHALLENGE_TTL
        });

        emit ChallengeIssued(msg.sender, challenge, block.timestamp + CHALLENGE_TTL);
    }

    function authenticate(uint256 guess) external {
        Challenge storage challenge = activeChallenges[msg.sender];

        require(block.timestamp <= challenge.expiresAt, "Challenge expired");
        require(challenge.value == guess, "Invalid guess");

        delete activeChallenges[msg.sender];

        emit Authenticated(msg.sender);
    }
}

/// @notice Intruder trying to predict or replay entropy authentication
contract EntropyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function predictChallenge() external view returns (uint256) {
        // Predict challenge in insecure contract (if using block.timestamp)
        return uint256(keccak256(abi.encodePacked(block.timestamp, address(this))));
    }

    function attackAuthenticate(uint256 guess) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("authenticate(uint256)", guess)
        );
    }
}
