// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectLinkingEmbeddingAttackDefense - Attack and Defense Simulation for Object Linking and Embedding in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Vulnerable Contract (Open Linking Without Validation, Unsafe Embedded Object Usage)
contract InsecureLinkingEmbedding {
    address public linkedContract; // Mutable and no access control

    struct ExternalData {
        uint256 value;
        bool isValid;
    }

    mapping(address => ExternalData) public embeddedData;

    event Linked(address indexed newLinkedContract);
    event DataUpdated(address indexed user, uint256 value, bool isValid);

    function link(address _external) external {
        linkedContract = _external;
        emit Linked(_external);
    }

    function updateEmbeddedData(uint256 value) external {
        // No validation of external update logic!
        embeddedData[msg.sender] = ExternalData(value, true);
        emit DataUpdated(msg.sender, value, true);
    }

    function delegateUnsafe() external {
        (bool success, ) = linkedContract.delegatecall(
            abi.encodeWithSignature("externalLogic()")
        );
        require(success, "Delegatecall failed");
    }
}

/// @notice Secure Contract (Immutable Linking, Scoped Embedding, Secure Delegate)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureLinkingEmbedding is Ownable {
    address public immutable trustedLinkedContract;

    struct ExternalData {
        uint256 value;
        bool isValid;
    }

    mapping(address => ExternalData) private embeddedData;

    event DataUpdated(address indexed user, uint256 value, bool isValid);

    constructor(address _trustedLinked) {
        require(_trustedLinked != address(0), "Invalid linked address");
        trustedLinkedContract = _trustedLinked;
    }

    function updateEmbeddedData(uint256 value) external {
        require(value < 1_000_000, "Value exceeds limits"); // sanity check
        embeddedData[msg.sender] = ExternalData(value, true);
        emit DataUpdated(msg.sender, value, true);
    }

    function secureDelegate() external onlyOwner {
        (bool success, ) = trustedLinkedContract.delegatecall(
            abi.encodeWithSignature("externalLogic()")
        );
        require(success, "Secure delegatecall failed");
    }

    function getEmbeddedData(address user) external view returns (uint256, bool) {
        ExternalData memory data = embeddedData[user];
        return (data.value, data.isValid);
    }
}

/// @notice Attack contract simulating linked contract upgrade
contract LinkIntruder {
    function externalLogic() external {
        // maliciously modify storage of the caller contract!
        assembly {
            sstore(0x0, 0xdeadbeef)
        }
    }
}
