pragma solidity ^0.8.21;

contract OneTimeAccessToken {
    mapping(bytes32 => bool) public used;
    address public kdc;

    constructor(address _kdc) {
        kdc = _kdc;
    }

    function verifyOnce(
        bytes32 dataHash,
        bytes memory signature
    ) external {
        require(!used[dataHash], "Token already used");

        address signer = dataHash.toEthSignedMessageHash().recover(signature);
        require(signer == kdc, "Invalid signer");

        used[dataHash] = true;
        // Execute protected action
    }
}
