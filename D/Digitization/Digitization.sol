pragma solidity ^0.8.0;

// Digitization contract for managing digital representations of assets
contract Digitization {
    // Struct to store digital asset metadata
    struct DigitalAsset {
        string name; // Name of the asset
        string description; // Description of the asset
        string dataHash; // Hash of the digital asset (e.g., IPFS or document hash)
        address owner; // Owner of the digital asset
        uint256 creationTime; // Timestamp of digitization
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for metadata
    }

    // Mapping from asset ID to DigitalAsset struct
    mapping(uint256 => DigitalAsset) public assets;
    uint256 public assetCount; // Counter for asset IDs

    // Event emitted when a new asset is digitized
    event AssetDigitized(uint256 assetId, string name, address owner, uint256 creationTime);
    // Event emitted when an asset is verified
    event AssetVerified(uint256 assetId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 assetId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 assetId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 assetId, address newOwner);

    // Modifier to check if caller is the asset owner
    modifier onlyOwner(uint256 _assetId) {
        require(assets[_assetId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if asset exists
    modifier assetExists(uint256 _assetId) {
        require(_assetId > 0 && _assetId <= assetCount, "Asset does not exist");
        _;
    }

    // Function to digitize a new asset
    function digitizeAsset(string memory _name, string memory _description, string memory _dataHash) public {
        assetCount++;
        DigitalAsset storage newAsset = assets[assetCount];
        newAsset.name = _name;
        newAsset.description = _description;
        newAsset.dataHash = _dataHash;
        newAsset.owner = msg.sender;
        newAsset.creationTime = block.timestamp;
        newAsset.isVerified = false; // Asset starts unverified
        newAsset.authorizedViewers[msg.sender] = true; // Owner gets view access

        emit AssetDigitized(assetCount, _name, msg.sender, block.timestamp);
    }

    // Function to verify an asset (e.g., by an authorized entity)
    function verifyAsset(uint256 _assetId) public assetExists(_assetId) {
        // In a real implementation, restrict this to a specific verifier role
        require(!assets[_assetId].isVerified, "Asset already verified");
        assets[_assetId].isVerified = true;
        emit AssetVerified(_assetId, msg.sender);
    }

    // Function to grant view access to an asset's metadata
    function grantAccess(uint256 _assetId, address _viewer) public onlyOwner(_assetId) assetExists(_assetId) {
        require(_viewer != address(0), "Invalid viewer address");
        assets[_assetId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_assetId, _viewer);
    }

    // Function to revoke view access to an asset's metadata
    function revokeAccess(uint256 _assetId, address _viewer) public onlyOwner(_assetId) assetExists(_assetId) {
        require(_viewer != assets[_assetId].owner, "Cannot revoke owner's access");
        assets[_assetId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_assetId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _assetId, address _viewer) public view assetExists(_assetId) returns (bool) {
        return assets[_assetId].authorizedViewers[_viewer];
    }

    // Function to get asset metadata (only for authorized viewers)
    function getAssetMetadata(uint256 _assetId) 
        public 
        view 
        assetExists(_assetId) 
        returns (string memory name, string memory description, string memory dataHash, address owner, uint256 creationTime, bool isVerified) 
    {
        require(assets[_assetId].authorizedViewers[msg.sender], "Access denied");
        DigitalAsset storage asset = assets[_assetId];
        return (asset.name, asset.description, asset.dataHash, asset.owner, asset.creationTime, asset.isVerified);
    }

    // Function to transfer ownership of an asset
    function transferOwnership(uint256 _assetId, address _newOwner) public onlyOwner(_assetId) assetExists(_assetId) {
        require(_newOwner != address(0), "Invalid new owner address");
        assets[_assetId].owner = _newOwner;
        assets[_assetId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_assetId, _newOwner);
    }
}