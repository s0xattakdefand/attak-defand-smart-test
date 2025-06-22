contract RSAChallengeGate {
    mapping(address => bool) public passed;

    function verifyAndEnter(uint256 m, uint256 s, uint256 e, uint256 n) external {
        require(modExp(s, e, n) == m, "Invalid signature");
        passed[msg.sender] = true;
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        return _modexp(base, exp, mod); // use same logic as above
    }
}
