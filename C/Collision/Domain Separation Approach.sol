// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Other Type C: 
 * Domain separation for multiple contexts or data 
 */
contract DomainSeparatedHash {
    /**
     * @dev Combine a domain prefix with the actual data to avoid 
     * collisions across different dApps or usage contexts.
     */
    function domainHash(
        string memory domain, 
        bytes memory data
    ) public pure returns (bytes32) 
    {
        // Typically we'd do `abi.encode(domain, data)` or a typed approach
        return keccak256(abi.encodePacked(domain, data));
    }
}
