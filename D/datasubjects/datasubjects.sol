// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATA SUBJECT PROTECTION DEMO
   NIST SP 800-188 / NIST SP 800-226 / NISTIR 8053 – “Persons to whom data refer”
   Illustrates:
     • VulnerableDataSubjectStore – stores PII publicly; anyone can read.
     • SafeDataSubjectRegistry     – only subjects can store/read, no enumeration.
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDataSubjectStore
----------------------------------------------------------------------------*/
contract VulnerableDataSubjectStore {
    struct Record {
        address subject;
        string  info;    // PII or data about the subject
    }

    mapping(uint256 => Record) public records;
    uint256 public recordCount;

    event RecordAdded(uint256 indexed id, address indexed subject, string info);

    /// Stores arbitrary info about any subject; info and subject are public.
    function addRecord(address subject, string calldata info) external {
        records[recordCount] = Record(subject, info);
        emit RecordAdded(recordCount, subject, info);
        recordCount++;
    }

    /// Anyone can read any record via the public mapping.
    function getRecord(uint256 id) external view returns (address subject, string memory info) {
        Record storage r = records[id];
        return (r.subject, r.info);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — SafeDataSubjectRegistry
   Subjects store and retrieve their own info; no public enumeration.
----------------------------------------------------------------------------*/
contract SafeDataSubjectRegistry {
    struct Record {
        string info;
    }

    mapping(address => Record) private subjectRecords;

    event MyRecordAdded(address indexed subject);
    event MyRecordRemoved(address indexed subject);

    /// Subject stores or updates their own info.
    function addOrUpdateMyInfo(string calldata info) external {
        subjectRecords[msg.sender] = Record(info);
        emit MyRecordAdded(msg.sender);
    }

    /// Subject removes their own info.
    function removeMyInfo() external {
        delete subjectRecords[msg.sender];
        emit MyRecordRemoved(msg.sender);
    }

    /// Subject retrieves their own info.
    function getMyInfo() external view returns (string memory) {
        return subjectRecords[msg.sender].info;
    }
}

/*=============================================================================
   HOW THE SAFE VERSION PROTECTS DATA SUBJECTS:
   • Confidentiality: records are private, keyed by subject address.
   • No enumeration: no way to list all subjects or their data.
   • Autonomy: only subjects can add, update, or remove their own info.
=============================================================================*/
