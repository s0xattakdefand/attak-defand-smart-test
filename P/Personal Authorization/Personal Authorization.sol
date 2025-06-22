// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PersonalAuthorizationAttackDefense - Attack and Defense Simulation for Personal Authorization in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Personal Authorization (Weak binding, No Replay Protection)
contract InsecurePersonalAuthorization {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount, bytes calldata signature) external {
        // 🔥 Accept any signature that matches (no binding, no nonce, no expiry!)
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = messageHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signer");

        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }
}

/// @notice Secure Personal Authorization with Full Nonce, Binding, and Expiry Control
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecurePersonalAuthorization is Ownable {
    using ECDSA for bytes32;

    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public usedAuthorizations;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function secureWithdraw(
        uint256 amount,
        uint256 nonce,
        uint256 expiryBlock,
        bytes calldata signature
    ) external {
        require(block.number <= expiryBlock, "Authorization expired");

        bytes32 authHash = keccak256(abi.encodePacked(msg.sender, amount, nonce, expiryBlock, address(this), block.chainid));
        require(!usedAuthorizations[authHash], "Authorization already used");

        address signer = authHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signer");

        usedAuthorizations[authHash] = true;

        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }
}

/// @notice Attack contract simulating replay or injection using stolen authorization
contract PersonalIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function replayWithdrawal(uint256 amount, bytes calldata stolenSignature) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(uint256,bytes)", amount, stolenSignature)
        );
    }
}
