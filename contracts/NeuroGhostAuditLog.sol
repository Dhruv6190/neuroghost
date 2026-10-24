// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title NeuroGhost audit log
/// @notice Stores fingerprints of NeuroGhost decisions (quarantine, approve, purge, blocked payment)
///         so nobody can quietly rewrite what the agent's guard decided. No memory text is stored.
contract NeuroGhostAuditLog {
    struct Entry {
        bytes32 entryHash;   // SHA-256 of the local audit entry (chained to the previous one)
        bytes32 contentHash; // SHA-256 of the memory text (or zero)
        uint8 action;        // 1 quarantined, 2 approved, 3 purged, 4 tx blocked, 5 halted, 6 reset
        uint64 timestamp;
        address recorder;
    }

    address public owner;
    mapping(address => bool) public recorders;
    Entry[] private entries;

    event DecisionRecorded(
        uint256 indexed index,
        bytes32 indexed entryHash,
        bytes32 contentHash,
        uint8 action,
        address recorder,
        uint64 timestamp
    );
    event RecorderSet(address indexed recorder, bool allowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyRecorder() {
        require(recorders[msg.sender], "not a recorder");
        _;
    }

    constructor() {
        owner = msg.sender;
        recorders[msg.sender] = true;
        emit RecorderSet(msg.sender, true);
    }

    function setRecorder(address recorder, bool allowed) external onlyOwner {
        recorders[recorder] = allowed;
        emit RecorderSet(recorder, allowed);
    }

    function record(bytes32 entryHash, bytes32 contentHash, uint8 action) external onlyRecorder returns (uint256 index) {
        require(action >= 1 && action <= 6, "bad action");
        index = entries.length;
        entries.push(Entry(entryHash, contentHash, action, uint64(block.timestamp), msg.sender));
        emit DecisionRecorded(index, entryHash, contentHash, action, msg.sender, uint64(block.timestamp));
    }

    function count() external view returns (uint256) {
        return entries.length;
    }

    function get(uint256 index) external view returns (Entry memory) {
        return entries[index];
    }
}
