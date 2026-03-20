# NFC APDU Specification

## Purpose
Defines the NFC command format for initiating a token-based bandwidth sharing session.

## Initial Command
Command name: TRANSFER_TOKEN

## Request Fields
- token_id
- requester_id
- token_value
- timestamp

## Response Fields
- status
- session_id
- approved_quota
- message

## Success Condition
- Status = 0x9000

## Failure Examples
- Invalid token
- Expired token
- Unsupported request
- Insufficient balance

## Notes
- Exact APDU byte layout will be finalized during NFC implementation
- Initial prototype may use a simplified payload structure