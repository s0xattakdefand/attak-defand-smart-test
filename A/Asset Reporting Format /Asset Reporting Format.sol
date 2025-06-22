// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssetReportingFormat - Report and log structured asset states for audit and visibility

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721 {
    function balanceOf(address owner) external view returns (uint256);
}

contract AssetReportingFormat {
    address public admin;

    enum AssetType { ERC20, ERC721, ERC1155, OTHER }

    struct AssetReport {
        AssetType assetType;
        address assetAddress;
        address holder;
        uint256 amount;
        string label;
        bytes32 metadataHash; // Optional hash of full external report
        uint256 timestamp;
    }

    bytes32[] public reportIds;
    mapping(bytes32 => AssetReport) public reports;

    event AssetReported(
        bytes32 indexed reportId,
        address indexed asset,
        address indexed holder,
        AssetType assetType,
        uint256 amount,
        string label
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportERC20(address token, address user, string calldata label, bytes32 metadataHash) external onlyAdmin {
        uint256 bal = IERC20(token).balanceOf(user);
        _storeReport(AssetType.ERC20, token, user, bal, label, metadataHash);
    }

    function reportERC721(address nft, address user, string calldata label, bytes32 metadataHash) external onlyAdmin {
        uint256 bal = IERC721(nft).balanceOf(user);
        _storeReport(AssetType.ERC721, nft, user, bal, label, metadataHash);
    }

    function _storeReport(
        AssetType atype,
        address asset,
        address holder,
        uint256 amount,
        string memory label,
        bytes32 metadataHash
    ) internal {
        bytes32 reportId = keccak256(abi.encodePacked(asset, holder, block.timestamp));
        reports[reportId] = AssetReport({
            assetType: atype,
            assetAddress: asset,
            holder: holder,
            amount: amount,
            label: label,
            metadataHash: metadataHash,
            timestamp: block.timestamp
        });
        reportIds.push(reportId);
        emit AssetReported(reportId, asset, holder, atype, amount, label);
    }

    function getAllReports() external view returns (bytes32[] memory) {
        return reportIds;
    }

    function getReport(bytes32 reportId) external view returns (AssetReport memory) {
        return reports[reportId];
    }
}
