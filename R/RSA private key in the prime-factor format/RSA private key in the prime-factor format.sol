// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RSAPrimeFactorAttackDefense - Attack and Defense Simulation for RSA Prime-Factor Key Exposure in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Prime Exposure (Leaking RSA Prime Factors Directly)
contract InsecureRSAPrime {
    uint256 public p;
    uint256 public q;
    uint256 public modulusN;

    event PrimesPublished(uint256 p, uint256 q);

    constructor(uint256 _p, uint256 _q) {
        p = _p;
        q = _q;
        modulusN = p * q;
        emit PrimesPublished(p, q); // 🔥 Dangerous: primes leaked publicly!
    }

    function getModulus() external view returns (uint256) {
        return modulusN;
    }
}

/// @notice Secure Prime Factor Handling (Only modulus exposed, primes never stored on-chain)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureRSAPrime is Ownable {
    uint256 public modulusN;
    bool public initialized;

    event ModulusRegistered(uint256 modulus);

    constructor() {}

    function registerModulus(uint256 _modulus) external onlyOwner {
        require(!initialized, "Already initialized");
        modulusN = _modulus;
        initialized = true;
        emit ModulusRegistered(modulusN);
    }

    function getModulus() external view returns (uint256) {
        return modulusN;
    }
}

/// @notice Attack contract trying to extract primes from insecure deployment
contract RSAIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function getExposedPrimes() external view returns (uint256 primeP, uint256 primeQ) {
        (, bytes memory dataP) = targetInsecure.staticcall(
            abi.encodeWithSignature("p()")
        );
        (, bytes memory dataQ) = targetInsecure.staticcall(
            abi.encodeWithSignature("q()")
        );

        primeP = abi.decode(dataP, (uint256));
        primeQ = abi.decode(dataQ, (uint256));
    }
}
