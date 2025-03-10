# LLM Security Client

A client library for implementing OWASP Top 10 security checks for LLM applications. This library helps developers integrate security best practices and real-time security updates into their LLM applications.

## Features

- 🔒 Prompt injection detection
- 🕵️ Sensitive information scanning
- ✅ Output validation
- 📊 Resource limit monitoring
- 🔄 Real-time security updates
- 📚 Access to latest security documentation

## Installation

```bash
npm install llm-security-client
```

## Quick Start

```javascript
const LLMSecurityClient = require('llm-security-client');

// Initialize the client
const client = new LLMSecurityClient({
  baseUrl: 'http://your-security-server.com',
  apiKey: 'your-api-key',
  maxTokens: 2000
});

// Example usage
async function securePrompt(userPrompt) {
  // Validate prompt before sending to LLM
  const validation = await client.validatePrompt(userPrompt);
  
  if (!validation.isValid) {
    console.log('Security risks detected:', validation.risks);
    console.log('Suggested mitigations:', validation.mitigations);
    return;
  }

  // Check resource limits
  const resourceCheck = await client.checkResourceLimits(userPrompt);
  if (!resourceCheck.isValid) {
    console.log('Request exceeds token limit:', resourceCheck);
    return;
  }

  // Process the prompt with your LLM...
  const llmResponse = await yourLLMFunction(userPrompt);

  // Validate LLM output
  const outputValidation = await client.validateOutput(llmResponse);
  if (!outputValidation.isValid) {
    console.log('Output risks detected:', outputValidation.risks);
    return;
  }

  return llmResponse;
}
```

## Security Features

### 1. Prompt Validation

```javascript
const promptValidation = await client.validatePrompt(userPrompt);
if (!promptValidation.isValid) {
  console.log('Risks:', promptValidation.risks);
  console.log('Mitigations:', promptValidation.mitigations);
}
```

### 2. Output Validation

```javascript
const outputValidation = await client.validateOutput(llmResponse);
if (!outputValidation.isValid) {
  console.log('Output risks:', outputValidation.risks);
}
```

### 3. Resource Management

```javascript
const resourceCheck = await client.checkResourceLimits(request);
if (!resourceCheck.isValid) {
  console.log(`Request exceeds token limit: ${resourceCheck.tokenCount}/${resourceCheck.maxTokens}`);
}
```

### 4. Security Updates Subscription

```javascript
// Subscribe to security updates
client.subscribeToUpdates('owasp_llm', (update) => {
  console.log('New security update:', update);
});

// Unsubscribe when done
client.unsubscribeFromUpdates('owasp_llm');
```

### 5. Access Security Documentation

```javascript
// Get latest OWASP LLM security documentation
const docs = await client.getSecurityDocs('llm');
console.log('Latest security guidelines:', docs);
```

## Configuration Options

```javascript
const client = new LLMSecurityClient({
  // Required
  apiKey: 'your-api-key',

  // Optional
  baseUrl: 'http://localhost:3000',
  wsUrl: 'ws://localhost:3000',
  autoReconnect: true,
  reconnectInterval: 5000,
  validateOutputs: true,
  maxTokens: 2000,
  
  // Enable/disable specific security checks
  securityChecks: {
    promptInjection: true,
    sensitiveInfo: true,
    outputValidation: true,
    resourceLimits: true
  }
});
```

## Security Best Practices

1. **API Key Security**
   - Store your API key securely
   - Use environment variables
   - Never expose the key in client-side code

2. **Prompt Validation**
   - Always validate user inputs
   - Implement role-based access control
   - Use prompt templates when possible

3. **Output Handling**
   - Validate all LLM outputs
   - Implement content filtering
   - Use proper escaping for different contexts

4. **Resource Management**
   - Set appropriate token limits
   - Implement rate limiting
   - Monitor resource usage

5. **Regular Updates**
   - Subscribe to security updates
   - Keep the client library updated
   - Review security documentation regularly

## Error Handling

```javascript
try {
  const validation = await client.validatePrompt(userPrompt);
  // Handle validation result
} catch (error) {
  console.error('Security check failed:', error.message);
  // Implement appropriate error handling
}
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details 