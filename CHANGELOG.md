# Changelog

## [0.4.0] - 2025-06-08
### Changed
- Major refactor: Now uses a custom FlowSession and the prn callback of AsyncSniffer for all flow processing, instead of relying on Scapy's DefaultSession/session system.
- All flow logic, feature extraction, and output are now fully managed by the project code, not by Scapy internals.
- The process method always returns None, preventing unwanted packet printing by Scapy.
- Logging is robust: only shows debug output if -v is set.
- All flows are always flushed at the end, even for small pcaps.

### Notes
- This project is a CICFlowMeter-like tool (see https://www.unb.ca/cic/research/applications.html#CICFlowMeter), not Cisco NetFlow. It extracts custom flow features as in the original Java CICFlowMeter.
- The refactor does not change the set of features/fields extracted, only how packets are routed to your logic.
