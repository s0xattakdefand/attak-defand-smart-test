pragma solidity ^0.8.0;

// DIMM contract for managing digital immutable memory modules
contract DIMM {
    // Struct to store memory module metadata
    struct MemoryModule {
        string moduleName; // Name of the memory module (e.g., DDR4 RDIMM)
        string specsHash; // Hash of module specifications (e.g., IPFS hash)
        address owner; // Owner of the module
        uint256 registrationTime; // Timestamp of registration
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for metadata
    }

    // Mapping from module ID to MemoryModule struct
    mapping(uint256 => MemoryModule) public modules;
    uint256 public moduleCount; // Counter for module IDs

    // Event emitted when a new module is registered
    event ModuleRegistered(uint256 moduleId, string moduleName, address owner, uint256 registrationTime);
    // Event emitted when a module is verified
    event ModuleVerified(uint256 moduleId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 moduleId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 moduleId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 moduleId, address newOwner);

    // Modifier to check if caller is the module owner
    modifier onlyOwner(uint256 _moduleId) {
        require(modules[_moduleId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if module exists
    modifier moduleExists(uint256 _moduleId) {
        require(_moduleId > 0 && _moduleId <= moduleCount, "Module does not exist");
        _;
    }

    // Function to register a new memory module
    function registerModule(string memory _moduleName, string memory _specsHash) public {
        moduleCount++;
        MemoryModule storage newModule = modules[moduleCount];
        newModule.moduleName = _moduleName;
        newModule.specsHash = _specsHash;
        newModule.owner = msg.sender;
        newModule.registrationTime = block.timestamp;
        newModule.isVerified = false; // Module starts unverified
        newModule.authorizedViewers[msg.sender] = true; // Owner gets view access

        emit ModuleRegistered(moduleCount, _moduleName, msg.sender, block.timestamp);
    }

    // Function to verify a module (e.g., by an authorized entity)
    function verifyModule(uint256 _moduleId) public moduleExists(_moduleId) {
        // In production, restrict to a specific verifier role
        require(!modules[_moduleId].isVerified, "Module already verified");
        modules[_moduleId].isVerified = true;
        emit ModuleVerified(_moduleId, msg.sender);
    }

    // Function to grant view access to a module's metadata
    function grantAccess(uint256 _moduleId, address _viewer) public onlyOwner(_moduleId) moduleExists(_moduleId) {
        require(_viewer != address(0), "Invalid viewer address");
        modules[_moduleId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_moduleId, _viewer);
    }

    // Function to revoke view access to a module's metadata
    function revokeAccess(uint256 _moduleId, address _viewer) public onlyOwner(_moduleId) moduleExists(_moduleId) {
        require(_viewer != modules[_moduleId].owner, "Cannot revoke owner's access");
        modules[_moduleId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_moduleId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _moduleId, address _viewer) public view moduleExists(_moduleId) returns (bool) {
        return modules[_moduleId].authorizedViewers[_viewer];
    }

    // Function to get module metadata (only for authorized viewers)
    function getModuleMetadata(uint256 _moduleId) 
        public 
        view 
        moduleExists(_moduleId) 
        returns (string memory moduleName, string memory specsHash, address owner, uint256 registrationTime, bool isVerified) 
    {
        require(modules[_moduleId].authorizedViewers[msg.sender], "Access denied");
        MemoryModule storage module = modules[_moduleId];
        return (module.moduleName, module.specsHash, module.owner, module.registrationTime, module.isVerified);
    }

    // Function to transfer ownership of a module
    function transferOwnership(uint256 _moduleId, address _newOwner) public onlyOwner(_moduleId) moduleExists(_moduleId) {
        require(_newOwner != address(0), "Invalid new owner address");
        modules[_moduleId].owner = _newOwner;
        modules[_moduleId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_moduleId, _newOwner);
    }
}