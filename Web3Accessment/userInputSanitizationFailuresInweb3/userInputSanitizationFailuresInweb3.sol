// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title InputSanitizationAttackDefense - Full Attack and Defense Simulation for User Input Sanitization Failures in Web3 Contracts
/// @author ChatGPT

/// @notice Secure smart contract enforcing input sanitization
contract SecureInputSanitization {
    address public owner;
    uint256 public constant MAX_ALLOWED_VALUE = 1000 ether;
    uint256 public constant MAX_STRING_LENGTH = 256;

    mapping(address => string) private userNicknames;
    mapping(address => uint256) public deposits;

    event NicknameSet(address indexed user, string nickname);
    event Deposited(address indexed user, uint256 amount);

    modifier onlyValidDeposit(uint256 _amount) {
        require(_amount > 0 && _amount <= MAX_ALLOWED_VALUE, "Invalid deposit amount");
        _;
    }

    modifier validateString(string memory _str) {
        require(bytes(_str).length > 0 && bytes(_str).length <= MAX_STRING_LENGTH, "Invalid string length");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setNickname(string calldata _nickname) external validateString(_nickname) {
        userNicknames[msg.sender] = _nickname;
        emit NicknameSet(msg.sender, _nickname);
    }

    function deposit() external payable onlyValidDeposit(msg.value) {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function getNickname(address user) external view returns (string memory) {
        return userNicknames[user];
    }
}

/// @notice Attack contract trying to bypass input sanitization
contract InputIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryOversizedDeposit() external payable returns (bool success) {
        (success, ) = target.call{value: 1001 ether}(
            abi.encodeWithSignature("deposit()")
        );
    }

    function tryLongNickname(string calldata longNickname) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("setNickname(string)", longNickname)
        );
    }
}
