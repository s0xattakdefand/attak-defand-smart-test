// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AppPropertyTemplateRegistry {
    struct Template {
        address creator;
        string name;
        string version;
        bytes32 configHash; // keccak256(app properties struct)
        bool active;
    }

    struct AppProperty {
        string key;
        string value;
        bool mutableByAdmin;
    }

    mapping(bytes32 => Template) public templates;
    mapping(bytes32 => mapping(string => AppProperty)) public properties;
    address public admin;

    event TemplateRegistered(bytes32 indexed id, string name, string version);
    event PropertySet(bytes32 indexed templateId, string key, string value);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyTemplateCreator(bytes32 id) {
        require(msg.sender == templates[id].creator, "Not template owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerTemplate(string calldata name, string calldata version, bytes32 configHash) external returns (bytes32) {
        bytes32 id = keccak256(abi.encodePacked(name, version, msg.sender, configHash));
        require(templates[id].creator == address(0), "Template already exists");

        templates[id] = Template({
            creator: msg.sender,
            name: name,
            version: version,
            configHash: configHash,
            active: true
        });

        emit TemplateRegistered(id, name, version);
        return id;
    }

    function setProperty(bytes32 id, string calldata key, string calldata value) external {
        AppProperty storage prop = properties[id][key];
        require(templates[id].active, "Template inactive");
        if (prop.mutableByAdmin) {
            require(msg.sender == admin || msg.sender == templates[id].creator, "Not authorized");
        } else {
            require(prop.value == "", "Immutable property");
            require(msg.sender == templates[id].creator, "Only creator can set");
        }

        prop.key = key;
        prop.value = value;
        emit PropertySet(id, key, value);
    }

    function setMutableFlag(bytes32 id, string calldata key, bool flag) external onlyTemplateCreator(id) {
        properties[id][key].mutableByAdmin = flag;
    }

    function getProperty(bytes32 id, string calldata key) external view returns (string memory) {
        return properties[id][key].value;
    }

    function getTemplate(bytes32 id) external view returns (Template memory) {
        return templates[id];
    }
}
