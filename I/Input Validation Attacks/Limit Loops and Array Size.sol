function batchMint(address[] calldata recipients) external {
    require(recipients.length <= 100, "Too many recipients");
    for (uint256 i = 0; i < recipients.length; i++) {
        _mint(recipients[i]);
    }
}
