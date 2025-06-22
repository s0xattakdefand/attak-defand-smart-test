// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DynamicHostClientProtocolAttackDefense - Full Attack and Defense Simulation for Dynamic Host Client Protocol (DHCP) Inspired Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Dynamic Host-Client Address Registry with Proofs and Expiry
contract SecureDynamicHostRegistry {
    address public owner;
    uint256 public leaseDuration = 1 days;
    uint256 public leaseBuffer = 1 hours; // Small window to renew

    struct HostInfo {
        address serviceAddress;
        uint256 leaseExpiry;
    }

    mapping(bytes32 => HostInfo) public registeredHosts;
    mapping(bytes32 => bool) public usedSignatures;

    event HostRegistered(bytes32 indexed hostId, address indexed service, uint256 leaseExpiry);
    event HostRenewed(bytes32 indexed hostId, address indexed service, uint256 leaseExpiry);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerHost(
        bytes32 hostId,
        address serviceAddress,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(serviceAddress != address(0), "Invalid service address");

        bytes32 messageHash = keccak256(abi.encodePacked(hostId, serviceAddress, address(this)));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == owner, "Unauthorized signer");
        require(!usedSignatures[messageHash], "Signature already used");

        registeredHosts[hostId] = HostInfo({
            serviceAddress: serviceAddress,
            leaseExpiry: block.timestamp + leaseDuration
        });

        usedSignatures[messageHash] = true;
        emit HostRegistered(hostId, serviceAddress, block.timestamp + leaseDuration);
    }

    function renewHost(bytes32 hostId) external {
        HostInfo storage info = registeredHosts[hostId];
        require(info.serviceAddress == msg.sender, "Not authorized host");
        require(block.timestamp <= info.leaseExpiry + leaseBuffer, "Lease expired");

        info.leaseExpiry = block.timestamp + leaseDuration;

        emit HostRenewed(hostId, msg.sender, info.leaseExpiry);
    }

    function getHostInfo(bytes32 hostId) external view returns (address serviceAddress, uint256 leaseExpiry) {
        HostInfo memory info = registeredHosts[hostId];
        return (info.serviceAddress, info.leaseExpiry);
    }
}

/// @notice Attack contract trying to hijack dynamic host registry
contract DynamicHostIntruder {
    address public targetRegistry;

    constructor(address _targetRegistry) {
        targetRegistry = _targetRegistry;
    }

    function fakeHostRegistration(bytes32 hostId, address fakeService) external returns (bool success) {
        (success, ) = targetRegistry.call(
            abi.encodeWithSignature("registerHost(bytes32,address,uint8,bytes32,bytes32)", hostId, fakeService, 27, bytes32(0), bytes32(0))
        );
    }
}
