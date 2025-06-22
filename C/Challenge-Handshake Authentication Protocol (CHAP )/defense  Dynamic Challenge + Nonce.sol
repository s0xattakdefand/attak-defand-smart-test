pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/blob/v2.5.1/contracts/cryptography/EIP712.sol";

contract Authentication {
    // Mapping user addresses to their challenges.
    mapping(address => bytes32) public usersChallenge;
    
 struct EIP712Domain {
       string   name;
       string version;
       uint256 chainId;
       address verifyingContract
  }

struct DomainType is EIP712Domain{
     function hash(struct EIP712Domain d,bytes memory s) internal pure returns (uint256){
        return keccak256(abi.encode((keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)") ,0x06fdce59,d.name,d.version,d.chainId.verifyingContract),s));
    }

,d   function createNewUser() external returns (bytes32 challengeHash) {
        require(msg.sender != address(0), "Sender cannot be zero");
        
        // Generate a new random number for the challenge
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(block.timestamp)));
        
        bytes memory hashedRandomNumber = abi.encodePacked(randomNumber);
        bytes32 challengeHash = keccak256(hashedRandomNumber);

        usersChallenge[msg.sender] = challengeHash;
        
        return (challengeHash);
    }
    
   function respond(bytes calldata signature) external {
       require(usersChallenge[msg.sender]!=bytes32(0), "No Challenge");
       
      address recoveredAddress= ecrecover(
            keccak256(abi.encodePacked("EIP712Domain", usersChallenge[msg.sender])),
            bytes32(uint256(now)),
           msg.sender,
             signature
        );
        
    // Must match the caller

       require(recoveredAddress ==  msg.sender, "Invalid Signature");
   }
}