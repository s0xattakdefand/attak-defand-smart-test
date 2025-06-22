// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BGPGatewayValidator {
    using ECDSA for bytes32;

    address public trustedRouteAnnouncer;
    mapping(address => bool) public approvedGateways;

    event RouteAnnounced(address gateway, string domain);

    constructor(address _trustedAnnouncer) {
        trustedRouteAnnouncer = _trustedAnnouncer;
    }

    function announceRoute(string calldata domain, uint256 nonce, bytes calldata sig) public {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, domain, nonce)).toEthSignedMessageHash();
        address signer = hash.recover(sig);
        require(signer == trustedRouteAnnouncer, "Unauthorized route");

        approvedGateways[msg.sender] = true;
        emit RouteAnnounced(msg.sender, domain);
    }

    function isGatewayApproved(address gateway) public view returns (bool) {
        return approvedGateways[gateway];
    }
}
