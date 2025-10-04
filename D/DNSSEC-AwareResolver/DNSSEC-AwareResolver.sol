// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DNSSEC-Aware Resolver
 * @dev A simplified smart contract simulating a DNSSEC-aware resolver.
 * This contract supports recursive domain resolution and DNSSEC signature verification.
 * It is an educational example and uses basic ECDSA signature verification.
 * For production, integrate with an oracle like ENS DNSSECOracle for full chain-of-trust verification.
 */
contract DNSSECAwareResolver is Ownable {
    constructor(address initialOwner) Ownable(initialOwner) {
        // Initialize the contract with the provided owner
    }

    struct DomainRecord {
        address owner;
        string data; // e.g., IP address, CNAME, or other resolution data
        uint256 registrationTime;
        bool active;
    }

    struct DNSSECProof {
        bytes signature;
        bytes32 messageHash;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    mapping(string => DomainRecord) public domains;
    mapping(bytes32 => bool) public usedSignatures; // Prevent replay attacks
    bytes32 public rootAnchor; // Simplified DNSSEC root anchor

    event DomainRegistered(string indexed domain, address indexed owner, uint256 timestamp);
    event DomainUpdated(string indexed domain, address indexed owner, string data);
    event SignatureVerified(string indexed domain, bool success);
    event DomainResolved(string indexed domain, string data);

    /**
     * @dev Register a new domain with DNSSEC proof.
     * @param domain The domain name (e.g., "example.com").
     * @param data The resolution data (e.g., IP address or CNAME).
     * @param proof The DNSSEC signature proof.
     */
    function registerDomain(
        string memory domain,
        string memory data,
        DNSSECProof memory proof
    ) public {
        require(bytes(domain).length > 0, "Invalid domain");
        require(domains[domain].owner == address(0), "Domain already registered");

        // Basic signature verification (in production, use full DNSSEC chain verification)
        bytes32 sigHash = keccak256(abi.encodePacked(domain, msg.sender, data));
        require(sigHash == proof.messageHash, "Invalid message hash");
        require(!usedSignatures[proof.messageHash], "Signature already used");
        usedSignatures[proof.messageHash] = true;

        // Verify ECDSA signature (simplified; assumes DNSSEC key is an Ethereum address)
        address signer = ecrecover(proof.messageHash, proof.v, proof.r, proof.s);
        require(signer != address(0), "Invalid signature");
        // In real implementation, verify signer against DNSSEC chain via oracle

        domains[domain] = DomainRecord({
            owner: msg.sender,
            data: data,
            registrationTime: block.timestamp,
            active: true
        });

        emit DomainRegistered(domain, msg.sender, block.timestamp);
        emit SignatureVerified(domain, true);
    }

    /**
     * @dev Recursively resolve a domain by checking parent domains if needed.
     * @param domain The domain name (e.g., "sub.example.com").
     * @return The resolution data or empty string if not found.
     */
    function resolve(string memory domain) public returns (string memory) {
        DomainRecord memory record = domains[domain];
        if (record.active) {
            emit DomainResolved(domain, record.data);
            return record.data;
        }

        // Attempt recursive resolution by checking parent domains
        string memory parentDomain = getParentDomain(domain);
        while (bytes(parentDomain).length > 0) {
            record = domains[parentDomain];
            if (record.active) {
                emit DomainResolved(domain, record.data);
                return record.data; // Return parent data as fallback
            }
            parentDomain = getParentDomain(parentDomain);
        }

        revert("Domain not found or inactive");
    }

    /**
     * @dev Helper function to extract parent domain (e.g., "sub.example.com" -> "example.com").
     * @param domain The domain name.
     * @return The parent domain or empty string if no parent exists.
     */
    function getParentDomain(string memory domain) internal pure returns (string memory) {
        bytes memory domainBytes = bytes(domain);
        uint256 dotIndex = 0;
        for (uint256 i = 0; i < domainBytes.length; i++) {
            if (domainBytes[i] == ".") {
                dotIndex = i;
                break;
            }
        }
        if (dotIndex == 0 || dotIndex == domainBytes.length - 1) {
            return "";
        }
        bytes memory parent = new bytes(domainBytes.length - dotIndex - 1);
        for (uint256 i = 0; i < parent.length; i++) {
            parent[i] = domainBytes[dotIndex + 1 + i];
        }
        return string(parent);
    }

    /**
     * @dev Update domain data (only owner).
     * @param domain The domain name.
     * @param newData The new resolution data.
     */
    function updateDomain(string memory domain, string memory newData) public {
        DomainRecord storage record = domains[domain];
        require(record.owner == msg.sender, "Not domain owner");
        require(record.active, "Domain not active");

        record.data = newData;
        emit DomainUpdated(domain, msg.sender, newData);
    }

    /**
     * @dev Transfer domain ownership.
     * @param domain The domain name.
     * @param newOwner The new owner address.
     */
    function transferDomain(string memory domain, address newOwner) public {
        DomainRecord storage record = domains[domain];
        require(record.owner == msg.sender, "Not domain owner");
        require(newOwner != address(0), "Invalid new owner");

        record.owner = newOwner;
        emit DomainUpdated(domain, newOwner, record.data);
    }

    /**
     * @dev Deactivate a domain (only owner).
     * @param domain The domain name.
     */
    function deactivateDomain(string memory domain) public {
        DomainRecord storage record = domains[domain];
        require(record.owner == msg.sender, "Not domain owner");

        record.active = false;
    }

    /**
     * @dev Owner can update the DNSSEC root anchor.
     * In production, this would be hardcoded or managed via multisig.
     * @param newAnchor The new root anchor hash.
     */
    function updateRootAnchor(bytes32 newAnchor) public onlyOwner {
        rootAnchor = newAnchor;
        // In production, validate against DNS root zone's public keys
    }
}