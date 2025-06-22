// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LaplaceMechanismAttackDefense - Full Attack and Defense Simulation for Laplace Mechanism in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Laplace Mechanism (Low Entropy, Reused Noise)
contract InsecureLaplaceMechanism {
    mapping(address => uint256) public noisyValues;

    event NoisySubmitted(address indexed user, uint256 noisyResult);

    function submit(uint256 trueValue) external {
        uint256 noise = uint256(keccak256(abi.encodePacked(block.timestamp))) % 5;
        uint256 noisyResult = trueValue + noise; // BAD: predictable timestamp noise
        noisyValues[msg.sender] = noisyResult;
        emit NoisySubmitted(msg.sender, noisyResult);
    }

    function getNoisy(address user) external view returns (uint256) {
        return noisyValues[user];
    }
}

/// @notice Secure Laplace Mechanism (High Entropy + Fresh Randomized Noise Per Query)
contract SecureLaplaceMechanism {
    mapping(address => uint256) public noisyValues;
    mapping(address => uint256) public nonces;
    uint256 public constant NOISE_SCALE = 5;

    event FreshNoisySubmitted(address indexed user, uint256 noisyResult);

    function submit(uint256 trueValue) external {
        uint256 noiseSeed = uint256(
            keccak256(
                abi.encodePacked(
                    msg.sender,
                    nonces[msg.sender],
                    block.prevrandao,
                    gasleft(),
                    address(this)
                )
            )
        );

        uint256 noiseMagnitude = noiseSeed % (2 * NOISE_SCALE);
        int256 signedNoise = int256(noiseMagnitude) - int256(NOISE_SCALE); // Center around 0
        uint256 noisyResult = uint256(int256(trueValue) + signedNoise);

        noisyValues[msg.sender] = noisyResult;
        nonces[msg.sender] += 1;

        emit FreshNoisySubmitted(msg.sender, noisyResult);
    }

    function getNoisy(address user) external view returns (uint256) {
        return noisyValues[user];
    }
}

/// @notice Attack contract simulating replay attacks on noisy systems
contract LaplaceMechanismIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replayQuery(address victim) external view returns (uint256 leakedValue) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("getNoisy(address)", victim)
        );
        leakedValue = abi.decode(data, (uint256));
    }
}
