pragma solidity ^0.8.0;

// DigitalVideoRecorder contract for managing video metadata and access
contract DigitalVideoRecorder {
    // Struct to store video metadata
    struct Video {
        string title; // Title of the video
        string ipfsHash; // IPFS hash for video content storage
        address owner; // Owner of the video
        uint256 timestamp; // Time of registration
        mapping(address => bool) accessList; // Access control list
    }

    // Mapping from video ID to Video struct
    mapping(uint256 => Video) public videos;
    uint256 public videoCount; // Counter for video IDs

    // Event emitted when a new video is registered
    event VideoRegistered(uint256 videoId, string title, address owner, uint256 timestamp);
    // Event emitted when access is granted
    event AccessGranted(uint256 videoId, address user);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 videoId, address user);

    // Modifier to check if caller is the video owner
    modifier onlyOwner(uint256 _videoId) {
        require(videos[_videoId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if video exists
    modifier videoExists(uint256 _videoId) {
        require(_videoId > 0 && _videoId <= videoCount, "Video does not exist");
        _;
    }

    // Function to register a new video
    function registerVideo(string memory _title, string memory _ipfsHash) public {
        videoCount++;
        Video storage newVideo = videos[videoCount];
        newVideo.title = _title;
        newVideo.ipfsHash = _ipfsHash;
        newVideo.owner = msg.sender;
        newVideo.timestamp = block.timestamp;
        newVideo.accessList[msg.sender] = true; // Owner gets access by default

        emit VideoRegistered(videoCount, _title, msg.sender, block.timestamp);
    }

    // Function to grant access to a video
    function grantAccess(uint256 _videoId, address _user) public onlyOwner(_videoId) videoExists(_videoId) {
        require(_user != address(0), "Invalid user address");
        videos[_videoId].accessList[_user] = true;
        emit AccessGranted(_videoId, _user);
    }

    // Function to revoke access to a video
    function revokeAccess(uint256 _videoId, address _user) public onlyOwner(_videoId) videoExists(_videoId) {
        require(_user != videos[_videoId].owner, "Cannot revoke owner's access");
        videos[_videoId].accessList[_user] = false;
        emit AccessRevoked(_videoId, _user);
    }

    // Function to check if a user has access to a video
    function hasAccess(uint256 _videoId, address _user) public view videoExists(_videoId) returns (bool) {
        return videos[_videoId].accessList[_user];
    }

    // Function to get video metadata (only accessible by authorized users)
    function getVideoMetadata(uint256 _videoId) public view videoExists(_videoId) returns (string memory title, string memory ipfsHash, address owner, uint256 timestamp) {
        require(videos[_videoId].accessList[msg.sender], "Access denied");
        Video storage video = videos[_videoId];
        return (video.title, video.ipfsHash, video.owner, video.timestamp);
    }

    // Function to transfer ownership of a video
    function transferOwnership(uint256 _videoId, address _newOwner) public onlyOwner(_videoId) videoExists(_videoId) {
        require(_newOwner != address(0), "Invalid new owner address");
        videos[_videoId].owner = _newOwner;
        videos[_videoId].accessList[_newOwner] = true; // Grant access to new owner
    }
}