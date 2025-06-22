contract EmergencyWithdrawal {
    mapping(address => uint256) public deposits;
    bool public emergency = false;

    function toggleEmergency(bool state) external {
        emergency = state;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function emergencyWithdraw() external {
        require(emergency, "Only in emergency");
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
