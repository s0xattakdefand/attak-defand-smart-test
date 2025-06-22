pragma solidity ^0.8.21;

contract IntrusionDetectionSystem {
    address public admin;
    mapping(address => bool) private authorizedEntities;
    mapping(address => uint256) public interactionCounts;
    uint256 public constant INTERACTION_THRESHOLD = 5;

    event UnauthorizedAccessAttempt(address indexed intruder);
    event ThresholdExceeded(address indexed entity, uint256 count);
    event AuthorizedEntityAdded(address indexed entity);
    event AuthorizedEntityRemoved(address indexed entity);

    constructor() {
        admin = msg.sender;
        authorizedEntities[admin] = true;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier detectIntrusion() {
        interactionCounts[msg.sender] += 1;

        if (!authorizedEntities[msg.sender]) {
            emit UnauthorizedAccessAttempt(msg.sender);
            revert("Unauthorized access detected");
        }

        if (interactionCounts[msg.sender] > INTERACTION_THRESHOLD) {
            emit ThresholdExceeded(msg.sender, interactionCounts[msg.sender]);
        }
        _;
    }

    function addAuthorizedEntity(address entity) external onlyAdmin {
        authorizedEntities[entity] = true;
        emit AuthorizedEntityAdded(entity);
    }

    function removeAuthorizedEntity(address entity) external onlyAdmin {
        authorizedEntities[entity] = false;
        emit AuthorizedEntityRemoved(entity);
    }

    function sensitiveAction() external detectIntrusion {
        // Critical or sensitive operations performed here
    }

    function isAuthorized(address entity) external view returns (bool) {
        return authorizedEntities[entity];
    }
}
