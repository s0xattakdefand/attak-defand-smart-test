// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DNSSEC-Aware Stub Resolver
 * @dev A simplified smart contract simulating a DNSSEC-aware stub resolver.
 * This contract supports basic domain resolution, DNSSEC signature verification,
 * and forwarding unresolved queries to a trusted recursive resolver.
 * It is an educational example using ECDSA for signature verification.
 * For production, integrate with an oracle like ENS DNSSECOracle for full chain-of-trust verification.
 */
contract DNSSECAwareStubResolver is Ownable {
    address public trustedResolver; // Address of trusted recursive resolver
    bytes32 public rootAnchor; // Simplified DNSSEC root anchor

    constructor(address initialOwner, address _trustedResolver) Ownable(initialOwner) {
        require(_trustedResolver != address(0), "Invalid trusted resolver address");
        trustedResolver = _trustedResolver;
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

    event DomainRegistered(string indexed domain, address indexed owner, uint256 timestamp);
    event DomainUpdated(string indexed domain, address indexed owner, string data);
    event SignatureVerified(string indexed domain, bool success);
    event QueryForwarded(string indexed domain, address resolver);
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
     * @dev Resolve a domain, checking local records or forwarding to trusted resolver.
     * @param domain The domain name (e.g., "example.com").
     * @return The resolution data or empty string if forwarded.
     */
    function resolve(string memory domain) public returns (string memory) {
        DomainRecord memory record = domains[domain];
        if (record.active) {
            emit DomainResolved(domain, record.data);
            return record.data;
        }

        // Forward to trusted recursive resolver (simulated)
        emit QueryForwarded(domain, trustedResolver);
        // In production, call trustedResolver's resolve function via interface
        // For simplicity, return empty string to indicate forwarded query
        return "";
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
     * @dev Update the trusted recursive resolver address (only owner).
     * @param newResolver The new resolver address.
     */
    function updateTrustedResolver(address newResolver) public onlyOwner {
        require(newResolver != address(0), "Invalid resolver address");
        trustedResolver = newResolver;
    }

    /**
     * @dev Update the DNSSEC root anchor (only owner).
     * In production, this would be hardcoded or managed via multisig.
     * @param newAnchor The new root anchor hash.
     */
    function updateRootAnchor(bytes32 newAnchor) public onlyOwner {
        rootAnchor = newAnchor;
        // In production, validate against DNS root zone's public keys
    }
}