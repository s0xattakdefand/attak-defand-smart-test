contract RoleBasedAuthorization {
    address public owner;
    mapping(address => bool) public isEditor;
    uint256 public contentValue;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyEditor() {
        require(isEditor[msg.sender], "Not an editor");
        _;
    }

    function assignEditor(address user, bool status) public onlyOwner {
        isEditor[user] = status;
    }

    function updateContent(uint256 newValue) public onlyEditor {
        contentValue = newValue;
    }
}
