// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DelegationSigner contract for managing delegated signing and execution
contract DelegationSigner {
    // Owner of the contract
    address public owner;

    // Domain separator for EIP-712
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    // Typehash for delegation struct
    bytes32 public constant DELEGATION_TYPEHASH = keccak256(
        "Delegation(address delegator,address delegatee,bytes action,uint256 nonce,uint256 deadline)"
    );

    // Structure to represent a delegation
    struct Delegation {
        address delegator; // Address authorizing the action
        address delegatee; // Address authorized to perform the action
        bytes action; // Encoded action data (e.g., function call)
        uint256 nonce; // Nonce to prevent replay attacks
        uint256 deadline; // Expiration time of the delegation
    }

    // Mapping to track nonces for each delegator to prevent replay attacks
    mapping(address => uint256) public nonces;

    // Event emitted when a delegation is executed
    event DelegationExecuted(address indexed delegator, address indexed delegatee, bytes action, uint256 nonce);

    // Event emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Constructor to initialize the owner and EIP-712 domain separator
    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("DelegationSigner")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // Function to execute a delegated action with signature verification
    function executeDelegation(
        address delegator,
        address delegatee,
        bytes calldata action,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        require(delegatee == msg.sender, "Caller must be the delegatee");
        require(block.timestamp <= deadline, "Delegation expired");

        // Get and increment nonce
        uint256 nonce = nonces[delegator]++;
        
        // Compute the digest for EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATION_TYPEHASH,
                delegator,
                delegatee,
                keccak256(action),
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                structHash
            )
        );

        // Verify the signature
        address signer = ecrecover(digest, v, r, s);
        require(signer == delegator && signer != address(0), "Invalid signature");

        // Execute the action
        (success, ) = address(this).call(action);
        require(success, "Action execution failed");

        emit DelegationExecuted(delegator, delegatee, action, nonce);
    }

    // Function to get the current nonce for a delegator
    function getNonce(address delegator) external view returns (uint256) {
        return nonces[delegator];
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // Fallback function to receive encoded action calls
    receive() external payable {}
}