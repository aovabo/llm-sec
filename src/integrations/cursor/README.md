# Cursor Security Plugin for LLMs

A security plugin for Cursor that implements OWASP Top 10 security checks for LLMs. This plugin helps protect your LLM interactions within Cursor by providing real-time security validation and updates.

## Setup in Cursor

1. Open Cursor settings
2. Navigate to the MCP Server section
3. Add the following configuration:

```json
{
  "mcp": {
    "server": {
      "url": "http://localhost:3000",
      "ws": "ws://localhost:3000"
    },
    "security": {
      "plugin": "cursor-llm-security",
      "config": {
        "validateBeforeSend": true,
        "validateResponses": true,
        "autoUpdate": true
      }
    }
  }
}
```

## Features

### 1. Real-time Security Validation
- Validates prompts before sending to Claude
- Checks responses for security issues
- Scans generated code for vulnerabilities

### 2. Security Updates
- Receives real-time security updates
- Automatically updates security rules
- Notifies about new security threats

### 3. Code Security Scanning
- Analyzes generated code for vulnerabilities
- Provides security recommendations
- Integrates with Cursor's code analysis

### 4. Resource Management
- Monitors token usage
- Prevents resource exhaustion
- Implements rate limiting

## Usage Examples

### Basic Setup
```javascript
const CursorSecurityPlugin = require('cursor-llm-security');

const security = new CursorSecurityPlugin({
  apiKey: 'your-api-key',
  validateBeforeSend: true,
  validateResponses: true
});
```

### Validate Prompts
```javascript
// Before sending to Claude
const validation = await security.validateCursorPrompt(userPrompt);
if (!validation.isValid) {
  console.log('Security risks:', validation.risks);
  console.log('Suggested fixes:', validation.mitigations);
}
```

### Scan Generated Code
```javascript
// After receiving code from Claude
const scan = await security.scanCode(generatedCode);
if (!scan.isValid) {
  console.log('Security issues:', scan.issues);
  console.log('Suggestions:', scan.suggestions);
}
```

### Access Security Documentation
```javascript
// Get latest security guidelines
const docs = await security.getSecurityGuidelines('llm');
console.log('Security best practices:', docs);
```

## Security Features

1. **Prompt Injection Protection**
   - Detects malicious prompts
   - Prevents system prompt leakage
   - Validates input boundaries

2. **Output Validation**
   - Checks for sensitive information
   - Validates generated code
   - Prevents harmful content

3. **Resource Management**
   - Token limit monitoring
   - Rate limiting
   - Resource usage tracking

4. **Real-time Updates**
   - Security rule updates
   - Vulnerability notifications
   - Best practice updates

## Configuration Options

```javascript
{
  // Connection
  baseUrl: 'http://localhost:3000',
  wsUrl: 'ws://localhost:3000',
  apiKey: 'your-api-key',

  // Validation
  validateBeforeSend: true,  // Validate prompts before sending
  validateResponses: true,   // Validate Claude's responses
  autoUpdate: true,         // Auto-update security rules

  // Resource limits
  maxTokens: 2000,
  rateLimit: 10,           // Requests per second

  // Notifications
  notifications: {
    security: true,        // Security alerts
    updates: true,         // Update notifications
    performance: true      // Resource usage alerts
  }
}
```

## Best Practices

1. **Always Validate Prompts**
   - Enable `validateBeforeSend`
   - Implement proper error handling
   - Review security warnings

2. **Monitor Responses**
   - Enable `validateResponses`
   - Check for sensitive data
   - Validate generated code

3. **Stay Updated**
   - Enable `autoUpdate`
   - Review security notifications
   - Keep the plugin updated

4. **Resource Management**
   - Set appropriate limits
   - Monitor usage
   - Implement rate limiting

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details 