// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Smart contract for Development Kit
contract DevelopmentKit is ReentrancyGuard, Ownable {
    // Struct to represent a developer
    struct Developer {
        address developerAddress;
        string name;
        bool isActive;
        uint256 joinDate;
    }

    // Struct to represent a smart contract template
    struct ContractTemplate {
        uint256 id;
        address creator;
        string name;
        string description;
        string ipfsHash; // Store contract source code or metadata on IPFS
        bool isActive;
    }

    // Struct to represent a test simulation
    struct TestSimulation {
        uint256 templateId;
        address tester;
        string inputData;
        string result;
        uint256 timestamp;
    }

    // State variables
    mapping(address => Developer) public developers;
    mapping(uint256 => ContractTemplate) public templates;
    mapping(uint256 => TestSimulation[]) public simulations;
    uint256 public developerCount;
    uint256 public templateCount;
    uint256 public simulationCount;

    // Events for transparency
    event DeveloperAdded(address indexed developer, string name, uint256 joinDate);
    event TemplateAdded(uint256 indexed templateId, address indexed creator, string name, string ipfsHash);
    event TemplateUpdated(uint256 indexed templateId, string name, string ipfsHash);
    event SimulationRun(uint256 indexed templateId, address indexed tester, string inputData, string result, uint256 timestamp);

    // Modifiers
    modifier onlyDeveloper() {
        require(developers[_msgSender()].isActive, "Only active developers can perform this action");
        _;
    }

    // Constructor to set the deployer as the initial owner
    constructor() Ownable(msg.sender) {
        developerCount = 0;
        templateCount = 0;
        simulationCount = 0;
    }

    // Function to add a new developer (only owner can add developers)
    function addDeveloper(address _developerAddress, string memory _name) external onlyOwner nonReentrant {
        require(_developerAddress != address(0), "Invalid address");
        require(!developers[_developerAddress].isActive, "Developer already exists");

        developers[_developerAddress] = Developer({
            developerAddress: _developerAddress,
            name: _name,
            isActive: true,
            joinDate: block.timestamp
        });
        developerCount++;

        emit DeveloperAdded(_developerAddress, _name, block.timestamp);
    }

    // Function to add a new contract template
    function addTemplate(string memory _name, string memory _description, string memory _ipfsHash) external onlyDeveloper nonReentrant {
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        uint256 templateId = templateCount;
        templates[templateId] = ContractTemplate({
            id: templateId,
            creator: _msgSender(),
            name: _name,
            description: _description,
            ipfsHash: _ipfsHash,
            isActive: true
        });
        templateCount++;

        emit TemplateAdded(templateId, _msgSender(), _name, _ipfsHash);
    }

    // Function to update an existing contract template
    function updateTemplate(uint256 _templateId, string memory _name, string memory _description, string memory _ipfsHash) external onlyDeveloper nonReentrant {
        ContractTemplate storage template = templates[_templateId];
        require(template.isActive, "Template does not exist or is inactive");
        require(template.creator == _msgSender(), "Only the creator can update the template");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        template.name = _name;
        template.description = _description;
        template.ipfsHash = _ipfsHash;

        emit TemplateUpdated(_templateId, _name, _ipfsHash);
    }

    // Function to simulate contract execution (dry-run)
    function runSimulation(uint256 _templateId, string memory _inputData) external onlyDeveloper nonReentrant returns (string memory) {
        ContractTemplate storage template = templates[_templateId];
        require(template.isActive, "Template does not exist or is inactive");

        // Simulate execution (in a real implementation, this could interact with a local node or VM)
        string memory result = string(abi.encodePacked("Simulated execution for template ", uint2str(_templateId), " with input: ", _inputData));

        simulations[_templateId].push(TestSimulation({
            templateId: _templateId,
            tester: _msgSender(),
            inputData: _inputData,
            result: result,
            timestamp: block.timestamp
        }));
        simulationCount++;

        emit SimulationRun(_templateId, _msgSender(), _inputData, result, block.timestamp);

        return result;
    }

    // Function to get template details
    function getTemplate(uint256 _templateId) external view returns (
        uint256 id,
        address creator,
        string memory name,
        string memory description,
        string memory ipfsHash,
        bool isActive
    ) {
        ContractTemplate storage template = templates[_templateId];
        require(template.isActive, "Template does not exist or is inactive");
        return (
            template.id,
            template.creator,
            template.name,
            template.description,
            template.ipfsHash,
            template.isActive
        );
    }

    // Function to get simulation details for a template
    function getSimulations(uint256 _templateId) external view returns (TestSimulation[] memory) {
        return simulations[_templateId];
    }

    // Function to check if an address is a developer
    function isDeveloper(address _address) external view returns (bool) {
        return developers[_address].isActive;
    }

    // Utility function to convert uint to string (for simulation result)
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        return string(bstr);
    }
}

// Notes:
// - This contract uses OpenZeppelin's ReentrancyGuard and Ownable for security.
// - IPFS hash is used to store contract source code or metadata off-chain, reducing gas costs.
// - The contract assumes a governance model where only the owner can add developers.
// - Simulation functionality is a placeholder; real-world use would integrate with a local blockchain or EVM.
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use, as per industry standards.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.