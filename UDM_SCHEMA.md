# Unified Data Model (UDM) / Elastic Common Schema (ECS) Implementation

## Overview

BlackStar SIEM now implements the Unified Data Model (UDM) based on Elastic Common Schema (ECS) standards for consistent log parsing and event categorization.

## UDM/ECS Fields

### Core Timestamp Fields
- **@timestamp**: ISO 8601 formatted timestamp (e.g., `2025-12-06T22:00:00.000Z`)
- **timestamp**: Python datetime object for internal processing

### Event Categorization Fields
- **event.kind**: Type of event (e.g., `event`, `alert`, `metric`)
- **event.category**: High-level event category (e.g., `network`, `authentication`, `file`, `process`)
- **event.type**: Event sub-type (e.g., `start`, `end`, `info`, `connection`, `access`)
- **event.action**: Specific action taken (e.g., `nmap_scan`, `ssh_login`, `failed_login`)
- **event.outcome**: Result of the action (e.g., `success`, `failure`)
- **event.severity**: Severity level (e.g., `low`, `medium`, `high`, `critical`)
- **event.dataset**: Dataset identifier (e.g., `blackstar.siem`)
- **event.module**: Module that generated the event (e.g., `blackstar`)

### Source Information
- **source.ip**: Source IP address
- **source.address**: Source address (can be IP, hostname, or other identifier)

### Destination Information
- **destination.ip**: Destination IP address
- **destination.address**: Destination address
- **destination.port**: Destination port number

### User Information
- **user.name**: Username associated with the event

### Host Information
- **host.name**: Hostname where the event occurred

### Agent Information
- **agent.type**: Type of agent that collected the event
- **agent.version**: Version of the agent

### Additional Fields
- **message**: Human-readable event description

## Event Type Mappings

### Network Events
- **nmap_scan**
  - category: `network`
  - type: `info`
  - kind: `event`
  - outcome: random (success/failure)

- **port_scan**
  - category: `network`
  - type: `connection`
  - kind: `event`
  - outcome: random (success/failure)

### Authentication Events
- **ssh_login**
  - category: `authentication`
  - type: `start`
  - kind: `event`
  - outcome: random (success/failure)

- **failed_login**
  - category: `authentication`
  - type: `start`
  - kind: `event`
  - outcome: `failure` (predetermined)

### File Events
- **file_access**
  - category: `file`
  - type: `access`
  - kind: `event`
  - outcome: random (success/failure)

### Process Events
- **process_creation**
  - category: `process`
  - type: `start`
  - kind: `event`
  - outcome: `success` (predetermined)

## Example Event Structure

```json
{
  "@timestamp": "2025-12-06T22:00:00.000Z",
  "timestamp": "2025-12-06 22:00:00",
  "event.kind": "event",
  "event.category": "authentication",
  "event.type": "start",
  "event.action": "ssh_login",
  "event.outcome": "success",
  "event.severity": "medium",
  "event.dataset": "blackstar.siem",
  "event.module": "blackstar",
  "source.ip": "192.168.1.100",
  "source.address": "192.168.1.100",
  "destination.ip": "192.168.1.50",
  "destination.address": "192.168.1.50",
  "destination.port": 22,
  "user.name": "admin",
  "message": "Security event detected: ssh_login",
  "host.name": "blackstar-siem-host",
  "agent.type": "blackstar-agent",
  "agent.version": "1.0.0"
}
```

## Benefits of UDM/ECS Implementation

1. **Standardization**: Consistent field naming across all events
2. **Interoperability**: Compatible with Elastic Stack and other SIEM tools
3. **Searchability**: Easier to query and correlate events
4. **Extensibility**: Easy to add new event types while maintaining consistency
5. **Best Practices**: Follows industry-standard security event logging

## Validation

All generated events (both sample and simulated) now conform to the UDM/ECS specification, ensuring proper categorization and making it easier to:
- Search for specific event types
- Create accurate alerts
- Build meaningful visualizations
- Integrate with external security tools

## References

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [ECS Event Categorization](https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html)
