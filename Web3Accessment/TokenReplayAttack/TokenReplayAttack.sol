// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TokenReplayAttackDefense - Full Attack and Defense Simulation for Token Replay Attacks (Signature Replays)
/// @author ChatGPT

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Secure token implementing anti-replay permit system
contract SecurePermitToken {
    string public constant name = "SecurePermitToken";
    string public constant version = "1";
    uint256 public immutable chainId;
    address public immutable verifyingContract;
    address public owner;

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    bytes32 public DOMAIN_SEPARATOR;

    event PermitUsed(address indexed owner, address indexed spender, uint256 amount, uint256 nonce);

    constructor() {
        uint256 _chainId;
        assembly {
            _chainId := chainid()
        }
        chainId = _chainId;
        verifyingContract = address(this);
        owner = msg.sender;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function permit(
        address _owner,
        address _spender,
        uint256 _value,
        uint256 _deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= _deadline, "Expired signature");
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(
                    PERMIT_TYPEHASH,
                    _owner,
                    _spender,
                    _value,
                    nonces[_owner]++,
                    _deadline
                ))
            )
        );

        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == _owner, "Invalid signature");

        // Execute transfer
        require(balances[_owner] >= _value, "Insufficient balance");
        balances[_owner] -= _value;
        balances[_spender] += _value;

        emit PermitUsed(_owner, _spender, _value, nonces[_owner]-1);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}

/// @notice Attack contract trying to replay a permit
contract TokenReplayIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryReplayPermit(
        address _owner,
        address _spender,
        uint256 _value,
        uint256 _usedNonce,
        uint256 _deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                _owner,
                _spender,
                _value,
                _deadline,
                v,
                r,
                s
            )
        );
    }
}
