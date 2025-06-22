// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenBinding {
    mapping(uint256 => address) public tokenOwner;

    event TokenBound(uint256 indexed tokenId, address indexed user);

    /**
     * @notice Bind a token to the caller (one-time only).
     * @param tokenId The ID of the token to bind.
     */
    function bindToken(uint256 tokenId) public {
        require(tokenOwner[tokenId] == address(0), "Token already bound");
        tokenOwner[tokenId] = msg.sender;

        emit TokenBound(tokenId, msg.sender);
    }

    /**
     * @notice Returns who a token is bound to.
     */
    function getBoundUser(uint256 tokenId) public view returns (address) {
        return tokenOwner[tokenId];
    }
}
