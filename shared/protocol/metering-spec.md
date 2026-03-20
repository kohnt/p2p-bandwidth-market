# Metering Specification

## Measurement Source
- Android NetworkStatsManager
- Tethering usage should be tracked using hotspot-related statistics where available

## Session Measurement Rule
- A session starts when requester access is approved
- A session ends when quota is exhausted or manually terminated

## Usage Calculation
- bytes_used = current_total_bytes - session_start_bytes

## Update Frequency
- Poll usage every 1 second during active session

## Cutoff Rule
- If bytes_used >= byte_quota, terminate access

## Notes
- Background traffic from the provider device must be accounted for carefully
- Session-level accuracy is more important than device-wide totals