// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AlternateMACRegistry {
    mapping(address => address) public alternateToPrimary;
    mapping(address => bool) public isAlternateRegistered;

    event AlternateMACRegistered(address indexed primary, address indexed alternate);
    event AlternateMACRevoked(address indexed alternate);

    /// @notice Register an alternate MAC address (off-chain signed)
    function registerAlternate(address alternate, bytes calldata signature) external {
        require(alternate != address(0), "Invalid address");
        require(!isAlternateRegistered[alternate], "Already registered");

        // Construct message to be signed by alternate
        bytes32 messageHash = getMessageHash(msg.sender, alternate);
        address recovered = recoverSigner(messageHash, signature);
        require(recovered == alternate, "Invalid signature from alternate");

        alternateToPrimary[alternate] = msg.sender;
        isAlternateRegistered[alternate] = true;

        emit AlternateMACRegistered(msg.sender, alternate);
    }

    /// @notice Revoke alternate MAC
    function revokeAlternate(address alternate) external {
        require(alternateToPrimary[alternate] == msg.sender, "Not owner");
        delete alternateToPrimary[alternate];
        delete isAlternateRegistered[alternate];

        emit AlternateMACRevoked(alternate);
    }

    /// @notice Get bound primary address
    function resolvePrimary(address alternate) external view returns (address) {
        return alternateToPrimary[alternate];
    }

    /// @notice Construct EIP-191 hash
    function getMessageHash(address primary, address alternate) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("AuthorizeAlternateMAC:", primary, alternate));
    }

    /// @notice ECDSA recover (standard 65-byte signature)
    function recoverSigner(bytes32 messageHash, bytes memory signature) public pure returns (address) {
        require(signature.length == 65, "Bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        return ecrecover(ethHash, v, r, s);
    }
}
