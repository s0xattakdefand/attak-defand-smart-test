// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Simplified DKIM-inspired smart contract for on-chain authentication
contract DKIM {
    // Mapping to store public keys for domains (simulating DNS TXT records)
    mapping(string => bytes) public domainPublicKeys;
    
    // Mapping to store domain owners
    mapping(string => address) public domainOwners;
    
    // Event emitted when a domain registers a public key
    event PublicKeyRegistered(string domain, bytes publicKey);
    
    // Event emitted when a message is verified
    event MessageVerified(string domain, bytes32 messageHash, bool isValid);
    
    // Modifier to restrict actions to domain owner
    modifier onlyDomainOwner(string memory domain) {
        require(domainOwners[domain] == msg.sender, "Not the domain owner");
        _;
    }
    
    // Constructor to set the deployer as the initial owner of a domain
    constructor(string memory initialDomain, bytes memory initialPublicKey) {
        require(bytes(initialDomain).length > 0, "Domain cannot be empty");
        require(initialPublicKey.length > 0, "Public key cannot be empty");
        domainOwners[initialDomain] = msg.sender;
        domainPublicKeys[initialDomain] = initialPublicKey;
        emit PublicKeyRegistered(initialDomain, initialPublicKey);
    }
    
    // Register or update a public key for a domain
    function registerPublicKey(string memory domain, bytes memory publicKey) 
        external 
        onlyDomainOwner(domain) 
    {
        require(bytes(domain).length > 0, "Domain cannot be empty");
        require(publicKey.length > 0, "Public key cannot be empty");
        domainPublicKeys[domain] = publicKey;
        emit PublicKeyRegistered(domain, publicKey);
    }
    
    // Transfer domain ownership
    function transferDomainOwnership(string memory domain, address newOwner) 
        external 
        onlyDomainOwner(domain) 
    {
        require(newOwner != address(0), "Invalid new owner address");
        domainOwners[domain] = newOwner;
    }
    
    // Verify a signed message (simulating DKIM signature verification)
    function verifyMessage(
        string memory domain,
        bytes32 messageHash,
        bytes memory signature
    ) 
        external 
        returns (bool) 
    {
        require(domainPublicKeys[domain].length > 0, "No public key for domain");
        
        // Recover the signer's address from the signature
        address signer = recoverSigner(messageHash, signature);
        
        // Check if the signer is the domain owner
        bool isValid = signer == domainOwners[domain];
        
        emit MessageVerified(domain, messageHash, isValid);
        return isValid;
    }
    
    // Helper function to recover the signer from a signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal 
        pure 
        returns (address) 
    {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        // Split the signature into r, s, and v components
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Ensure v is in the valid range (27 or 28)
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature 'v' value");
        
        // Recover the signer address
        return ecrecover(messageHash, v, r, s);
    }
    
    // Get the public key for a domain
    function getPublicKey(string memory domain) 
        external 
        view 
        returns (bytes memory) 
    {
        return domainPublicKeys[domain];
    }
    
    // Fallback function to prevent accidental ETH deposits
    receive() external payable {
        revert("Contract does not accept ETH");
    }
}