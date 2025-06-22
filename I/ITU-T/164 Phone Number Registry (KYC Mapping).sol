pragma solidity ^0.8.21;

contract E164PhoneRegistry {
    mapping(string => address) public phoneToWallet;
    mapping(address => string) public walletToPhone;

    event PhoneLinked(address indexed user, string phone);

    function linkPhone(string memory phone) external {
        require(bytes(walletToPhone[msg.sender]).length == 0, "Already linked");

        phoneToWallet[phone] = msg.sender;
        walletToPhone[msg.sender] = phone;

        emit PhoneLinked(msg.sender, phone);
    }

    function resolvePhone(string memory phone) external view returns (address) {
        return phoneToWallet[phone];
    }
}
