// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RSAChallengeGate {
    struct PubKey {
        uint256 e;
        uint256 n;
        string role;
    }

    mapping(address => PubKey) public keys;
    mapping(bytes32 => bool) public used; // prevent replay
    event Verified(address indexed sender, string role, bytes32 payloadHash);

    // === REGISTER RSA PubKey ===
    function register(uint256 e, uint256 n, string calldata role) external {
        keys[msg.sender] = PubKey(e, n, role);
    }

    // === VERIFY SIGNATURE + AUTHORIZE PAYLOAD ===
    function verifyPayload(
        address signer,
        bytes32 payloadHash,
        uint256 sig
    ) external returns (string memory role) {
        require(!used[payloadHash], "Already used");
        PubKey memory k = keys[signer];
        require(modExp(sig, k.e, k.n) == uint256(payloadHash), "Bad RSA sig");
        used[payloadHash] = true;

        emit Verified(signer, k.role, payloadHash);
        return k.role;
    }

    // === MOD EXP SIMULATOR (rsa_sig^e % n) ===
    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256 result) {
        result = 1;
        for (; exponent > 0; exponent >>= 1) {
            if (exponent & 1 > 0) result = mulmod(result, base, modulus);
            base = mulmod(base, base, modulus);
        }
    }
}
