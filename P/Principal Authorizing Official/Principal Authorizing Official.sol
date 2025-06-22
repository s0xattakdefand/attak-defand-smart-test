// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PrincipalAuthorizingOfficialAttackDefense - Attack and Defense Simulation for PAO Roles in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure PAO Management (Single PAO, No Signature Validation, No Rotation)
contract InsecurePAO {
    address public principalAuthorizingOfficial;

    event ActionAuthorized(address indexed by, string action);

    constructor() {
        principalAuthorizingOfficial = msg.sender;
    }

    function authorizeAction(string calldata action) external {
        // 🔥 No restriction — anyone can "authorize"!
        emit ActionAuthorized(msg.sender, action);
    }
}

/// @notice Secure PAO Management (Multi-Sig, Explicit Signature-Based Authorization, Rotation Mechanism)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePAO is Ownable {
    using ECDSA for bytes32;

    mapping(address => bool) private authorizedPAOs;
    uint256 public quorum;
    mapping(bytes32 => bool) private usedHashes;

    event PAOAdded(address indexed newPAO);
    event PAORemoved(address indexed oldPAO);
    event ActionAuthorized(address indexed by, string action);

    constructor(address[] memory initialPAOs, uint256 _quorum) {
        require(initialPAOs.length >= _quorum, "Not enough initial PAOs");
        for (uint256 i = 0; i < initialPAOs.length; i++) {
            authorizedPAOs[initialPAOs[i]] = true;
            emit PAOAdded(initialPAOs[i]);
        }
        quorum = _quorum;
    }

    function addPAO(address newPAO) external onlyOwner {
        authorizedPAOs[newPAO] = true;
        emit PAOAdded(newPAO);
    }

    function removePAO(address pao) external onlyOwner {
        authorizedPAOs[pao] = false;
        emit PAORemoved(pao);
    }

    function authorizeAction(
        string calldata action,
        bytes[] calldata signatures
    ) external {
        bytes32 actionHash = keccak256(abi.encodePacked(action, address(this), block.chainid));
        require(!usedHashes[actionHash], "Action already authorized");

        uint256 validSignatures;
        address[] memory seen = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = actionHash.toEthSignedMessageHash().recover(signatures[i]);
            require(authorizedPAOs[signer], "Invalid PAO signature");

            for (uint256 j = 0; j < validSignatures; j++) {
                require(seen[j] != signer, "Duplicate PAO signer");
            }
            seen[validSignatures] = signer;
            validSignatures++;
        }

        require(validSignatures >= quorum, "Not enough PAO approvals");

        usedHashes[actionHash] = true;
        emit ActionAuthorized(msg.sender, action);
    }

    function isPAO(address user) external view returns (bool) {
        return authorizedPAOs[user];
    }
}

/// @notice Attack contract simulating unauthorized action authorization
contract PAOIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeAuthorize(string calldata maliciousAction) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("authorizeAction(string)", maliciousAction)
        );
    }
}
