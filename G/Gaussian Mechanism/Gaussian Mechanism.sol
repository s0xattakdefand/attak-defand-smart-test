// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GaussianMechanismAttackDefense - Full Attack and Defense Simulation for Gaussian Mechanism in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Gaussian Mechanism (Low-Entropy, No Fresh Randomness)
contract InsecureGaussianMechanism {
    mapping(address => uint256) public data;
    uint256 public constant NOISE_MAGNITUDE = 5;

    event NoisyDataSubmitted(address indexed user, uint256 noisyResult);

    function submitData(uint256 trueValue) external {
        uint256 weakNoise = uint256(keccak256(abi.encodePacked(block.timestamp))) % NOISE_MAGNITUDE;
        uint256 noisyResult = trueValue + weakNoise; // BAD: Low entropy, timestamp-only
        data[msg.sender] = noisyResult;
        emit NoisyDataSubmitted(msg.sender, noisyResult);
    }

    function getNoisyData(address user) external view returns (uint256) {
        return data[user];
    }
}

/// @notice Secure Gaussian Mechanism (Fresh, High-Entropy Noise with Contextual Binding)
contract SecureGaussianMechanism {
    mapping(address => uint256) public data;
    uint256 public constant NOISE_MAGNITUDE = 10;

    event SecureNoisyDataSubmitted(address indexed user, uint256 noisyResult);

    function submitData(uint256 trueValue, uint256 nonce) external {
        uint256 noise = uint256(keccak256(abi.encodePacked(
            msg.sender,
            nonce,
            block.prevrandao,
            gasleft(),
            address(this)
        ))) % (2 * NOISE_MAGNITUDE); // Create noise between [0, 2*NOISE_MAGNITUDE)

        int256 signedNoise = int256(noise) - int256(NOISE_MAGNITUDE); // Center around 0
        uint256 noisyResult = uint256(int256(trueValue) + signedNoise);

        data[msg.sender] = noisyResult;
        emit SecureNoisyDataSubmitted(msg.sender, noisyResult);
    }

    function getNoisyData(address user) external view returns (uint256) {
        return data[user];
    }
}

/// @notice Attack contract simulating weak Gaussian replay attack
contract GaussianMechanismIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replayNoiseAttack(address victim) external view returns (uint256 leakedNoisyValue) {
        (, bytes memory output) = targetInsecure.staticcall(
            abi.encodeWithSignature("getNoisyData(address)", victim)
        );
        leakedNoisyValue = abi.decode(output, (uint256));
    }
}
