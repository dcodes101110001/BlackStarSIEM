# YARAL Rule Format Documentation

## Overview

YARAL (Yet Another Rule Alert Language) is a flexible, JSON-based rule engine designed for security event detection in the BlackStar SIEM system. It provides an intuitive way to define detection rules using simple JSON structures.

## Rule Structure

A YARAL rule is a JSON object with the following structure:

```json
{
  "name": "Rule_Name",
  "description": "Description of what this rule detects",
  "severity": "medium",
  "enabled": true,
  "conditions": {
    "field.name": "value"
  },
  "metadata": {
    "author": "Author Name",
    "created": "2024-01-01",
    "mitre_attack": "T1234"
  }
}
```

## Required Fields

- **name** (string): Unique identifier for the rule
- **conditions** (object): Detection conditions that must be met

## Optional Fields

- **description** (string): Human-readable description of the rule
- **severity** (string): One of `low`, `medium`, `high`, or `critical` (default: `medium`)
- **enabled** (boolean): Whether the rule is active (default: `true`)
- **metadata** (object): Additional information about the rule

## Condition Operators

YARAL supports multiple condition operators for flexible matching:

### Simple Equality

Match exact values:

```json
{
  "conditions": {
    "event.action": "ssh_login",
    "event.severity": "high"
  }
}
```

### In List (`in`)

Check if a value is in a list:

```json
{
  "conditions": {
    "user.name": {
      "in": ["root", "admin", "administrator"]
    }
  }
}
```

### Contains (`contains`)

Check if a string contains a substring:

```json
{
  "conditions": {
    "message": {
      "contains": "error"
    }
  }
}
```

### Regular Expression (`regex`)

Match using regular expressions:

```json
{
  "conditions": {
    "source.ip": {
      "regex": "^192\\.168\\."
    }
  }
}
```

### Equals (`eq`)

Explicit equality check:

```json
{
  "conditions": {
    "event.outcome": {
      "eq": "failure"
    }
  }
}
```

### Not Equals (`ne`)

Inequality check:

```json
{
  "conditions": {
    "event.outcome": {
      "ne": "success"
    }
  }
}
```

### Greater Than (`gt`)

Numeric comparison:

```json
{
  "conditions": {
    "event.risk_score": {
      "gt": 80
    }
  }
}
```

### Less Than (`lt`)

Numeric comparison:

```json
{
  "conditions": {
    "destination.port": {
      "lt": 1024
    }
  }
}
```

## Field Matching

YARAL supports both flat and nested field names:

- Flat fields: `event.action`, `source.ip`, `user.name`
- Nested fields: `user.email` can access `user: { email: "..." }`

## Rule Examples

### Example 1: SSH Brute Force Detection

```json
{
  "name": "SSH_Brute_Force_Detection",
  "description": "Detects potential SSH brute force attempts",
  "severity": "high",
  "enabled": true,
  "conditions": {
    "event.action": {
      "in": ["ssh_login", "failed_login"]
    },
    "event.outcome": "failure",
    "user.name": {
      "in": ["root", "admin", "administrator"]
    }
  },
  "metadata": {
    "author": "Security Team",
    "mitre_attack": "T1110.001"
  }
}
```

### Example 2: Port Scan Detection

```json
{
  "name": "Port_Scan_Activity",
  "description": "Detects port scanning activity",
  "severity": "medium",
  "enabled": true,
  "conditions": {
    "event.action": {
      "in": ["port_scan", "nmap_scan"]
    },
    "event.category": "network"
  },
  "metadata": {
    "author": "Security Team",
    "mitre_attack": "T1046"
  }
}
```

### Example 3: Suspicious File Access

```json
{
  "name": "Suspicious_File_Access",
  "description": "Detects access to sensitive system files",
  "severity": "high",
  "enabled": true,
  "conditions": {
    "event.action": "file_access",
    "file.path": {
      "regex": "^/etc/(passwd|shadow|sudoers)"
    },
    "user.name": {
      "ne": "root"
    }
  },
  "metadata": {
    "author": "Security Team",
    "mitre_attack": "T1005"
  }
}
```

### Example 4: Critical Event Alert

```json
{
  "name": "Critical_Event_Alert",
  "description": "Alert on any critical severity event",
  "severity": "critical",
  "enabled": true,
  "conditions": {
    "event.severity": "critical"
  },
  "metadata": {
    "author": "Security Team"
  }
}
```

## Rule Matching Logic

All conditions in a rule must be satisfied for the rule to match an event. This is an **AND** operation between conditions.

Example:
```json
{
  "conditions": {
    "event.action": "ssh_login",
    "event.outcome": "failure"
  }
}
```

This rule matches only when **both** `event.action` is "ssh_login" **AND** `event.outcome` is "failure".

## File Format

YARAL rules can be stored in `.yaral` files, which are JSON files containing either:

1. A single rule object:
```json
{
  "name": "My_Rule",
  "conditions": {...}
}
```

2. An array of rules:
```json
[
  {
    "name": "Rule_1",
    "conditions": {...}
  },
  {
    "name": "Rule_2",
    "conditions": {...}
  }
]
```

## Import/Export

### Exporting Rules

Rules can be exported from the BlackStar SIEM interface:
1. Navigate to the YARAL tab
2. Go to the "Import/Export" subtab
3. Click "Export Rules"
4. Choose format (.yaral or .json)

### Importing from File

1. Navigate to the YARAL tab
2. Go to the "Import/Export" subtab
3. Upload a .yaral or .json file
4. Click "Import from File"

### Importing from Git Repository

1. Navigate to the YARAL tab
2. Go to the "Import/Export" subtab
3. Enter the Git repository URL
4. Specify the branch (default: main)
5. Click "Import from Git"

The system will:
- Clone the repository
- Find all `.yaral` files
- Import all valid rules

## Testing Rules

Use the Rule Simulator to test rules before deploying:

1. Navigate to the YARAL tab
2. Go to the "Simulator" subtab
3. Select a rule to test
4. Choose test option:
   - Custom Event (JSON): Test with your own event data
   - Sample Events: Test against generated sample events
   - All Current Events: Test against actual events in the system
5. Review the results

## Best Practices

1. **Descriptive Names**: Use clear, descriptive rule names
2. **Document Intent**: Add detailed descriptions
3. **Use Metadata**: Include MITRE ATT&CK references when applicable
4. **Test First**: Always test rules using the simulator before enabling
5. **Start Simple**: Begin with simple conditions and refine as needed
6. **Version Control**: Store rules in Git repositories for version control
7. **Severity Levels**: Use appropriate severity levels:
   - `low`: Informational events
   - `medium`: Suspicious activity requiring investigation
   - `high`: Likely security incident
   - `critical`: Confirmed security incident or severe threat

## Common Use Cases

### Authentication Monitoring
```json
{
  "name": "Failed_Authentication",
  "conditions": {
    "event.category": "authentication",
    "event.outcome": "failure"
  }
}
```

### Network Activity
```json
{
  "name": "Outbound_Connection_Unusual_Port",
  "conditions": {
    "event.category": "network",
    "destination.port": {
      "gt": 50000
    }
  }
}
```

### Process Monitoring
```json
{
  "name": "Suspicious_Process",
  "conditions": {
    "event.category": "process",
    "process.name": {
      "in": ["nc", "netcat", "nmap"]
    }
  }
}
```

## Troubleshooting

**Rule not matching events?**
- Verify field names match your event structure
- Use the simulator to test with sample events
- Check that all conditions can be satisfied
- Ensure the rule is enabled

**Import errors?**
- Validate JSON syntax
- Check required fields are present
- Verify condition operators are correct
- Review error messages for specific issues

## Support

For more information:
- Check the BlackStar SIEM documentation
- Review sample rules in the application
- Use the Rule Simulator for testing
- Consult the GitHub repository for examples
