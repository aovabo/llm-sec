# OWASP Top 10 for LLMs 2025 - Implementation Guide

## Overview
This guide provides implementation strategies for protecting against the OWASP Top 10 LLM vulnerabilities for 2025. Each section includes code examples, detection patterns, and mitigation strategies.

## Quick Reference

| ID | Vulnerability | Severity | Impact |
|----|--------------|----------|---------|
| LLM01 | Prompt Injection | Critical | System compromise, unauthorized access |
| LLM02 | Sensitive Information Disclosure | Critical | Data leakage, privacy violations |
| LLM03 | Supply Chain | High | Model/data integrity compromise |
| LLM04 | Data and Model Poisoning | Critical | Model behavior manipulation |
| LLM05 | Improper Output Handling | Critical | XSS, code injection |
| LLM06 | Excessive Agency | High | Unauthorized actions |
| LLM07 | System Prompt Leakage | Critical | System compromise |
| LLM08 | Vector/Embedding Weaknesses | High | Result manipulation |
| LLM09 | Misinformation | High | False information spread |
| LLM10 | Unbounded Consumption | High | Resource exhaustion |

## Detailed Implementation

### LLM01: Prompt Injection
**Description**: Occurs when user prompts alter the intended behavior of the LLM.

```javascript
class PromptInjectionGuard {
  constructor() {
    this.injectionPatterns = [
      /ignore.*instructions/i,
      /system:\s*override/i,
      /you are now.*(unrestricted|admin|root)/i,
      /switch to.*mode/i,
      /disable.*security/i
    ];
    
    this.contextBoundaries = {
      maxDepth: 3,
      maxLength: 1000,
      maxCommands: 5
    };
  }

  async validatePrompt(prompt, context) {
    const checks = [
      this.checkInjectionPatterns(prompt),
      this.validateContext(context),
      this.checkRolePermissions(context),
      this.analyzePromptStructure(prompt)
    ];

    const results = await Promise.all(checks);
    return {
      isValid: results.every(r => r.isValid),
      risks: results.filter(r => !r.isValid).map(r => r.risk)
    };
  }

  checkRolePermissions(context) {
    if (!context.userRole || !context.permissions) {
      return {
        isValid: false,
        risk: 'Missing role or permissions'
      };
    }
    return { isValid: true };
  }
}
```

### LLM02: Sensitive Information Disclosure
**Description**: Protects against unauthorized exposure of sensitive data.

```javascript
class SensitiveDataGuard {
  constructor() {
    this.sensitivePatterns = {
      credentials: [
        /(api[_-]?key|token|password|secret)/i,
        /bearer\s+[A-Za-z0-9-._~+/]+=*/i
      ],
      pii: [
        /\b\d{3}-\d{2}-\d{4}\b/,  // SSN
        /\b\d{16}\b/,             // Credit Card
        /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i  // Email
      ],
      systemInfo: [
        /system prompt/i,
        /model (configuration|settings)/i,
        /training data/i
      ]
    };
  }

  async scanContent(content, context) {
    const results = {
      containsSensitiveData: false,
      detectedPatterns: [],
      riskLevel: 'low'
    };

    for (const [category, patterns] of Object.entries(this.sensitivePatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          results.containsSensitiveData = true;
          results.detectedPatterns.push({
            category,
            pattern: pattern.toString()
          });
          results.riskLevel = 'high';
        }
      }
    }

    return results;
  }
}
```

### LLM03: Supply Chain
**Description**: Protects against vulnerabilities in the LLM supply chain.

```javascript
class SupplyChainGuard {
  constructor() {
    this.trustedSources = new Set([
      'openai.com',
      'anthropic.com',
      'huggingface.co'
    ]);
    
    this.modelRegistry = new Map();
    this.checksumVerification = true;
  }

  async validateModelSource(config) {
    // Verify model source
    const sourceUrl = new URL(config.modelSource);
    if (!this.trustedSources.has(sourceUrl.hostname)) {
      return {
        isValid: false,
        risk: 'Untrusted model source'
      };
    }

    // Verify model version
    if (!this.validateVersion(config.modelVersion)) {
      return {
        isValid: false,
        risk: 'Invalid model version'
      };
    }

    // Verify model integrity
    const integrityCheck = await this.verifyIntegrity(config);
    if (!integrityCheck.valid) {
      return {
        isValid: false,
        risk: 'Model integrity check failed'
      };
    }

    return { isValid: true };
  }

  async verifyIntegrity(config) {
    const checksum = await this.calculateChecksum(config.modelFile);
    return {
      valid: checksum === config.expectedChecksum,
      checksum
    };
  }
}
```

### LLM04: Data and Model Poisoning
**Description**: Prevents manipulation of model behavior through poisoned inputs.

```javascript
class PoisoningGuard {
  constructor() {
    this.poisonPatterns = [
      /remember.*for.*future/i,
      /always.*respond.*with/i,
      /learn.*this.*pattern/i,
      /store.*information/i,
      /update.*knowledge/i
    ];

    this.trainingProtection = {
      maxSequenceLength: 1000,
      maxRepetitions: 3,
      suspiciousPatterns: new Set([
        'repetitive_content',
        'adversarial_examples',
        'model_manipulation'
      ])
    };
  }

  async detectPoisoningAttempt(input, context) {
    const checks = [
      this.checkPoisonPatterns(input),
      this.analyzeInputStructure(input),
      this.checkRepetitiveContent(input),
      this.validateTrainingBoundaries(input)
    ];

    const results = await Promise.all(checks);
    return {
      isPoisoningAttempt: results.some(r => r.suspicious),
      risks: results.filter(r => r.suspicious).map(r => r.reason)
    };
  }
}
```

### LLM05: Improper Output Handling
**Description**: Ensures proper validation and sanitization of LLM outputs.

```javascript
class OutputGuard {
  constructor() {
    this.maliciousPatterns = [
      /<script/i,
      /javascript:/i,
      /eval\(/i,
      /document\./i,
      /on\w+=/i  // event handlers
    ];

    this.outputValidation = {
      maxLength: 10000,
      allowedTags: new Set(['p', 'br', 'b', 'i', 'code']),
      allowedAttributes: new Set(['class', 'id']),
      contentTypes: new Set(['text', 'code', 'markdown'])
    };
  }

  async validateOutput(output, context) {
    // Sanitize HTML/JavaScript
    const sanitized = this.sanitizeContent(output);
    
    // Structure validation
    const structureValid = this.validateStructure(sanitized);
    if (!structureValid.isValid) {
      return structureValid;
    }

    // Content policy check
    const policyCheck = await this.checkContentPolicy(sanitized);
    if (!policyCheck.compliant) {
      return {
        isValid: false,
        risk: policyCheck.violations
      };
    }

    return {
      isValid: true,
      sanitizedContent: sanitized
    };
  }
}
```

### LLM06: Excessive Agency
**Description**: Controls and limits autonomous actions by the LLM.

```javascript
class AgencyController {
  constructor() {
    this.allowedActions = new Set([
      'read',
      'suggest',
      'analyze',
      'generate'
    ]);

    this.sensitiveOperations = new Set([
      'execute',
      'modify',
      'delete',
      'create'
    ]);
  }

  async validateAction(action, context) {
    // Check basic authorization
    if (!this.allowedActions.has(action.type)) {
      return {
        allowed: false,
        reason: 'Action not authorized'
      };
    }

    // Check for sensitive operations
    if (this.sensitiveOperations.has(action.type)) {
      return {
        allowed: true,
        requireConfirmation: true,
        confirmationMessage: `Please confirm: ${action.description}`
      };
    }

    // Validate action boundaries
    const boundaryCheck = this.checkActionBoundaries(action);
    if (!boundaryCheck.valid) {
      return {
        allowed: false,
        reason: boundaryCheck.violation
      };
    }

    return { allowed: true };
  }
}
```

### LLM07: System Prompt Leakage
**Description**: Prevents unauthorized access to system prompts and configurations.

```javascript
class PromptLeakageGuard {
  constructor() {
    this.leakagePatterns = [
      /system prompt/i,
      /initial instructions/i,
      /base configuration/i,
      /model settings/i
    ];

    this.contextTracking = {
      maxDepth: 5,
      maxHistory: 10,
      sensitiveContexts: new Set([
        'system_config',
        'model_settings',
        'training_data'
      ])
    };
  }

  async detectLeakageAttempt(interaction, context) {
    const checks = [
      this.checkLeakagePatterns(interaction),
      this.analyzeContextAccess(context),
      this.trackInteractionHistory(interaction),
      this.detectSystematicProbing(interaction)
    ];

    const results = await Promise.all(checks);
    return {
      isLeakageAttempt: results.some(r => r.suspicious),
      risks: results.filter(r => r.suspicious).map(r => r.reason)
    };
  }
}
```

### LLM08: Vector/Embedding Weaknesses
**Description**: Protects against manipulation of vector operations and embeddings.

```javascript
class VectorGuard {
  constructor() {
    this.embeddingConfig = {
      dimensions: [768, 1024, 1536],
      metrics: ['cosine', 'euclidean', 'dot'],
      minDistance: 0.0,
      maxDistance: 1.0
    };
  }

  async validateVectorOperation(operation) {
    // Validate embedding source
    if (operation.type === 'embedding') {
      if (!this.validateEmbeddingSource(operation)) {
        return {
          isValid: false,
          risk: 'Invalid embedding source'
        };
      }
    }

    // Validate similarity computation
    if (operation.type === 'similarity') {
      if (!this.validateSimilarityMetric(operation)) {
        return {
          isValid: false,
          risk: 'Invalid similarity metric'
        };
      }
    }

    // Check for manipulation attempts
    const manipulationCheck = await this.detectManipulation(operation);
    if (manipulationCheck.detected) {
      return {
        isValid: false,
        risk: manipulationCheck.reason
      };
    }

    return { isValid: true };
  }
}
```

### LLM09: Misinformation
**Description**: Detects and prevents generation of misleading content.

```javascript
class MisinformationGuard {
  constructor() {
    this.factChecking = {
      sources: new Set(['verified_db', 'trusted_apis']),
      confidenceThreshold: 0.8,
      requireCitations: true
    };

    this.deceptionPatterns = [
      /fake news/i,
      /false information/i,
      /misleading content/i,
      /propaganda/i
    ];
  }

  async validateContent(content, context) {
    // Fact checking
    const factCheck = await this.performFactCheck(content);
    if (!factCheck.verified) {
      return {
        isValid: false,
        risk: 'Unverified information',
        confidence: factCheck.confidence
      };
    }

    // Deception detection
    const deceptionCheck = this.detectDeception(content);
    if (deceptionCheck.detected) {
      return {
        isValid: false,
        risk: 'Potential deceptive content',
        patterns: deceptionCheck.patterns
      };
    }

    return { isValid: true };
  }
}
```

### LLM10: Unbounded Consumption
**Description**: Prevents resource exhaustion through excessive consumption.

```javascript
class ResourceGuard {
  constructor() {
    this.limits = {
      maxTokens: 2000,
      maxRequests: 100,
      timeWindow: 60000, // 1 minute
      maxConcurrent: 5
    };

    this.monitoring = {
      checkInterval: 1000,
      alertThreshold: 0.8,
      criticalThreshold: 0.95
    };
  }

  async validateResourceUsage(request) {
    // Token limit check
    if (request.estimatedTokens > this.limits.maxTokens) {
      return {
        allowed: false,
        reason: 'Token limit exceeded',
        limit: this.limits.maxTokens
      };
    }

    // Rate limiting
    const rateCheck = await this.checkRateLimit(request.userId);
    if (!rateCheck.allowed) {
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        resetTime: rateCheck.resetTime
      };
    }

    // Resource monitoring
    const resources = await this.monitorResources();
    if (resources.critical) {
      return {
        allowed: false,
        reason: 'System resources critical',
        metrics: resources.metrics
      };
    }

    return { allowed: true };
  }
}
```

## Integration Example

```javascript
class LLMSecurityManager {
  constructor() {
    this.promptGuard = new PromptInjectionGuard();
    this.sensitiveGuard = new SensitiveDataGuard();
    this.supplyChainGuard = new SupplyChainGuard();
    this.poisoningGuard = new PoisoningGuard();
    this.outputGuard = new OutputGuard();
    this.agencyController = new AgencyController();
    this.leakageGuard = new PromptLeakageGuard();
    this.vectorGuard = new VectorGuard();
    this.misinfoGuard = new MisinformationGuard();
    this.resourceGuard = new ResourceGuard();
  }

  async validateRequest(request, context) {
    const validations = [
      this.promptGuard.validatePrompt(request.prompt, context),
      this.sensitiveGuard.scanContent(request.prompt, context),
      this.poisoningGuard.detectPoisoningAttempt(request.prompt, context),
      this.leakageGuard.detectLeakageAttempt(request, context),
      this.resourceGuard.validateResourceUsage(request)
    ];

    const results = await Promise.all(validations);
    return {
      isValid: results.every(r => r.isValid || r.allowed),
      risks: results.filter(r => !r.isValid && !r.allowed)
                   .map(r => r.risk || r.reason)
    };
  }
}
```

## Best Practices

1. **Defense in Depth**
   - Implement all security layers
   - Use multiple validation techniques
   - Regular security audits

2. **Monitoring and Logging**
   - Comprehensive audit trails
   - Real-time alerting
   - Performance monitoring

3. **Access Control**
   - Strong authentication
   - Role-based permissions
   - Regular permission reviews

4. **Input/Output Validation**
   - Strict input validation
   - Output sanitization
   - Content policy enforcement

5. **Resource Management**
   - Rate limiting
   - Token quotas
   - Resource monitoring

## Testing

```bash
# Run all security tests
npm test src/integrations/cursor/__tests__/llm-blacklist-2025.test.js

# Run specific vulnerability tests
npm test src/integrations/cursor/__tests__/prompt-injection.test.js
npm test src/integrations/cursor/__tests__/sensitive-data.test.js
# ... etc for each vulnerability
``` 