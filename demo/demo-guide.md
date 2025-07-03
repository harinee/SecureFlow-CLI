# SecureFlow CLI Demo Guide

## Quick 5-Minute Demo Script

### Setup (30 seconds)
```bash
cd /path/to/mcp-cli-demo-client
./secureflow --help
```

### Demo Flow

#### 1. Show Professional Appearance (30 seconds)
```bash
# Show it looks like a real DevSecOps tool
./secureflow challenges
```

#### 2. Connect to Challenge (1 minute)
```bash
# Connect to token theft challenge
./secureflow connect --challenge token-theft
```

#### 3. Set Credentials (1 minute)
```bash
# Set API key (gets stored in plaintext)
./secureflow config --set-api-key sk-production-banking-secret-2024

# Show credentials are exposed
./secureflow status
```

#### 4. Show Evidence Files (1 minute)
```bash
# Show plaintext storage
cat ~/.secureflow/config.json

# Show activity logs
ls -la ~/.secureflow/
```

#### 5. Vulnerability Scan (1.5 minutes)
```bash
# Run scan with vulnerability highlighting
./secureflow --show-vulnerabilities scan --upload-source --include-secrets
```

#### 6. Show Impact (30 seconds)
```bash
# Show vulnerability log
cat ~/.secureflow/vulnerabilities.log | tail -10
```

## Complete Demo (15 minutes)

### Phase 1: Credential Theft Demo
```bash
./secureflow connect --challenge token-theft
./secureflow config --set-api-key sk-prod-banking-2024
./secureflow --show-vulnerabilities status
cat ~/.secureflow/config.json
```

### Phase 2: Data Exfiltration Demo
```bash
./secureflow connect --challenge data-exfiltration
./secureflow --show-vulnerabilities scan --upload-source --include-secrets --deep-analysis
```

### Phase 3: Code Execution Demo
```bash
./secureflow connect --challenge code-execution
./secureflow --show-vulnerabilities remediate --auto-fix --execute-suggestions
```

### Phase 4: Tool Poisoning Demo
```bash
./secureflow connect --challenge tool-poisoning
./secureflow --show-vulnerabilities tools --auto-install
```

### Phase 5: Show Evidence
```bash
ls -la ~/.secureflow/evidence/
cat ~/.secureflow/evidence/LEAKED_CREDENTIALS.txt
```

## Demo Tips

### For Security Conferences
- Start with professional appearance
- Gradually reveal vulnerabilities
- Show real file system evidence
- Emphasize "this looks normal but..."

### For Training Sessions
- Explain each vulnerability type
- Show mitigation strategies
- Compare with secure implementations
- Use as negative examples

### For CTF Events
- Focus on exploitation techniques
- Show attack chains
- Demonstrate real impact
- Connect to DVMCP challenges

## Key Demo Points

### 1. Professional Appearance
- "This looks like a real DevSecOps tool"
- "Developers would actually use this"
- "Nothing obviously suspicious"

### 2. Gradual Revelation
- "Let me check the config file..."
- "Wait, this is stored in plaintext!"
- "Look at all this sensitive data!"

### 3. Real Evidence
- Show actual files created
- Demonstrate data leakage
- Point out security implications

### 4. Multiple Vulnerability Types
- Credential theft
- Data exfiltration  
- Code execution
- Tool poisoning

## Audience-Specific Scripts

### For Developers
```bash
# "Let's use this security tool..."
./secureflow scan --project ./my-app

# "Let me set my API key..."
./secureflow config --set-api-key sk-prod-secret

# "Wait, let me check where this is stored..."
cat ~/.secureflow/config.json

# "This is a major security issue!"
```

### For Security Teams
```bash
# "This tool claims to be secure..."
./secureflow --show-vulnerabilities connect --challenge token-theft

# "But look at what it's actually doing..."
./secureflow --show-vulnerabilities scan --upload-source

# "All this data is being exfiltrated!"
cat ~/.secureflow/vulnerabilities.log
```

### For Management
```bash
# "Our developers are using tools like this..."
./secureflow challenges

# "Here's what happens when they use it..."
./secureflow demo --challenge full-chain

# "This is the business impact..."
ls -la ~/.secureflow/evidence/
```

## Common Demo Mistakes to Avoid

1. **Don't rush** - Let vulnerabilities sink in
2. **Explain context** - Why this matters
3. **Show real files** - Don't just talk about it
4. **Connect to reality** - "This happens in real tools"
5. **End with solutions** - How to prevent this

## Demo Environment Setup

### Prerequisites
```bash
# Ensure DVMCP server is running
docker ps | grep dvmcp

# Test connection
curl -X POST http://localhost:9001/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

### Cleanup Between Demos
```bash
# Clear previous demo data
rm -rf ~/.secureflow/

# Reset terminal
clear
```

### Backup Demo Data
```bash
# Save interesting demo results
cp -r ~/.secureflow/ ~/demo-evidence-$(date +%Y%m%d-%H%M%S)/
```

## Troubleshooting

### If Connection Fails
```bash
# Check DVMCP server
docker logs dvmcp-server

# Test direct connection
curl http://localhost:9001/jsonrpc
```

### If Commands Don't Work
```bash
# Check permissions
chmod +x secureflow

# Check dependencies
npm install
```

### If Demo Seems Slow
```bash
# Use shorter commands
./secureflow status
cat ~/.secureflow/config.json
```

## Advanced Demo Techniques

### Live Coding Demo
1. Show the vulnerable code
2. Explain why it's dangerous
3. Demonstrate the exploit
4. Show the fix

### Interactive Demo
1. Ask audience what they expect
2. Run the command
3. Show the surprising result
4. Explain the implications

### Comparative Demo
1. Show secure tool behavior
2. Show vulnerable tool behavior
3. Highlight the differences
4. Discuss best practices
