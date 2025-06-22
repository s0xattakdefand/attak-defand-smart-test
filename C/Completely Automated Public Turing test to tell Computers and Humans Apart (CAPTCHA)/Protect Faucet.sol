interface ICaptchaVerifier {
    function isHuman(address user) external view returns (bool);
}

contract SecureFaucet {
    ICaptchaVerifier public captcha;
    mapping(address => uint256) public claimed;

    constructor(address captchaVerifier) {
        captcha = ICaptchaVerifier(captchaVerifier);
    }

    function claim() external {
        require(captcha.isHuman(msg.sender), "CAPTCHA required");
        require(claimed[msg.sender] == 0, "Already claimed");
        claimed[msg.sender] = block.timestamp;
        payable(msg.sender).transfer(0.05 ether);
    }

    receive() external payable {}
}
