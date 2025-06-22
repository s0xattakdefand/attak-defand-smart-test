pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract KerberosAuth {
    using ECDSA for bytes32;

    address public kdc; // Trusted signer like Kerberos KDC
    mapping(bytes32 => bool) public usedTickets;

    event TicketUsed(address indexed user, bytes32 ticketHash);

    constructor(address _kdc) {
        kdc = _kdc;
    }

    function useTicket(
        address user,
        string memory serviceName,
        uint256 expiresAt,
        bytes memory signature
    ) external {
        require(block.timestamp <= expiresAt, "Ticket expired");

        bytes32 ticketHash = keccak256(abi.encodePacked(user, serviceName, expiresAt));
        require(!usedTickets[ticketHash], "Ticket already used");

        address recovered = ticketHash.toEthSignedMessageHash().recover(signature);
        require(recovered == kdc, "Invalid KDC signature");

        usedTickets[ticketHash] = true;
        emit TicketUsed(user, ticketHash);

        // Ticket validated — proceed with sensitive logic
    }
}
