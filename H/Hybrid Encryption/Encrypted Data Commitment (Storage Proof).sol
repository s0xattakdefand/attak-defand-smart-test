contract EncryptedNoteVault {
    struct Note {
        bytes32 encryptedKey; // AES_KEY encrypted with pubKey
        string encryptedDataCID; // e.g., IPFS hash
    }

    mapping(address => Note[]) public userNotes;

    function storeEncryptedNote(bytes32 _encryptedKey, string calldata _cid) external {
        userNotes[msg.sender].push(Note(_encryptedKey, _cid));
    }

    function getUserNotes(address user) external view returns (Note[] memory) {
        return userNotes[user];
    }
}
