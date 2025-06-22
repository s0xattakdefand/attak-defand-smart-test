// Detect known malicious payloads or addresses by signature hash
pragma solidity ^0.8.21;

contract SignatureBasedIDS {
    mapping(bytes32 => bool) public blacklistedSignatures;
    event MaliciousSignatureDetected(address sender, bytes data);

    function addMaliciousSignature(bytes calldata data) external {
        blacklistedSignatures[keccak256(data)] = true;
    }

    function secureAction(bytes calldata data) external {
        if (blacklistedSignatures[keccak256(data)]) {
            emit MaliciousSignatureDetected(msg.sender, data);
            revert("Blocked malicious signature");
        }
        // Continue processing...
    }
}
