contract CallTokenManager {
    mapping(address => uint256) public tokens;

    function depositTokens(uint256 amount) external {
        tokens[msg.sender] += amount;
    }

    function burnToken() internal {
        require(tokens[msg.sender] > 0, "[CAC] No tokens to burn");
        tokens[msg.sender]--;
    }
}

contract CallAdmissionToken is CallTokenManager {
    uint256 public callCount;

    function admittedAction() external {
        burnToken();
        callCount++;
    }
}
