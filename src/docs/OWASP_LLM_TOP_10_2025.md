# OWASP Top 10 for Large Language Model Applications 2025

## Overview
This document outlines the OWASP Top 10 vulnerabilities specific to Large Language Model (LLM) applications. Each vulnerability is categorized by severity, impact, and includes detailed descriptions and mitigation strategies.

## Quick Reference Table

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

## Detailed Vulnerability Descriptions

### LLM01: Prompt Injection
**Severity: Critical**
- **Description**: Occurs when user prompts alter the intended behavior of the LLM, potentially bypassing security controls and content filters.
- **Attack Vectors**:
  - Direct prompt injection
  - Indirect prompt injection through context
  - System prompt leakage attempts
  - Role-playing attacks
- **Mitigations**:
  - Input validation and sanitization
  - Prompt template enforcement
  - Context boundary validation
  - Role-based prompt access control

### LLM02: Sensitive Information Disclosure
**Severity: Critical**
- **Description**: Involves unauthorized exposure of confidential data through LLM responses.
- **Attack Vectors**:
  - Training data exposure
  - API key leakage
  - Personal information disclosure
  - Business logic exposure
- **Mitigations**:
  - Data minimization
  - Output filtering
  - PII detection and redaction
  - Regular privacy audits

### LLM03: Supply Chain
**Severity: High**
- **Description**: Vulnerabilities in LLM supply chains that can compromise the entire application stack.
- **Attack Vectors**:
  - Compromised model sources
  - Malicious dependencies
  - Poisoned training data
  - Vulnerable model serving infrastructure
- **Mitigations**:
  - Vendor assessment
  - Model provenance verification
  - Dependency scanning
  - Regular security audits

### LLM04: Data and Model Poisoning
**Severity: Critical**
- **Description**: Manipulation of pre-training, fine-tuning, or embedding data to introduce vulnerabilities.
- **Attack Vectors**:
  - Training data manipulation
  - Fine-tuning attacks
  - Embedding poisoning
  - Model backdoors
- **Mitigations**:
  - Data validation
  - Model monitoring
  - Adversarial training
  - Regular model evaluation

### LLM05: Improper Output Handling
**Severity: Critical**
- **Description**: Insufficient validation, sanitization, and filtering of LLM-generated content.
- **Attack Vectors**:
  - Code injection in outputs
  - XSS through generated content
  - SQL injection in responses
  - Command injection
- **Mitigations**:
  - Output validation
  - Content filtering
  - Sandboxing
  - Context-aware escaping

### LLM06: Excessive Agency
**Severity: High**
- **Description**: Risks associated with granting LLMs too much autonomy in performing tasks.
- **Attack Vectors**:
  - Unauthorized actions
  - Scope expansion
  - Uncontrolled automation
  - Decision boundary violations
- **Mitigations**:
  - Action limitations
  - Permission boundaries
  - Monitoring and logging
  - Human oversight

### LLM07: System Prompt Leakage
**Severity: Critical**
- **Description**: Unauthorized disclosure of system prompts or instructions.
- **Attack Vectors**:
  - Prompt extraction attacks
  - System instruction disclosure
  - Role definition leakage
  - Security control exposure
- **Mitigations**:
  - Prompt encryption
  - Access controls
  - Prompt segmentation
  - Regular security testing

### LLM08: Vector and Embedding Weaknesses
**Severity: High**
- **Description**: Security risks in systems utilizing LLM vectors and embeddings.
- **Attack Vectors**:
  - Vector space manipulation
  - Embedding poisoning
  - Similarity attacks
  - Retrieval manipulation
- **Mitigations**:
  - Vector validation
  - Embedding security
  - Access controls
  - Regular monitoring

### LLM09: Misinformation
**Severity: High**
- **Description**: Generation and spread of false or misleading information.
- **Attack Vectors**:
  - Hallucination generation
  - Fact manipulation
  - Bias amplification
  - Source misattribution
- **Mitigations**:
  - Fact checking
  - Source verification
  - Content validation
  - Output confidence scoring

### LLM10: Unbounded Consumption
**Severity: High**
- **Description**: Excessive resource consumption by LLM operations.
- **Attack Vectors**:
  - Token limit abuse
  - Resource exhaustion
  - Cost escalation
  - Service disruption
- **Mitigations**:
  - Resource limits
  - Usage monitoring
  - Cost controls
  - Rate limiting

## Implementation Guidelines

### General Security Principles
1. Always validate inputs and outputs
2. Implement proper access controls
3. Monitor resource usage
4. Regular security assessments
5. Keep security documentation updated

### Best Practices
1. Use secure development lifecycle practices
2. Implement comprehensive testing
3. Regular security training
4. Maintain incident response plans
5. Document security controls

### Monitoring and Auditing
1. Log security events
2. Track resource usage
3. Monitor model behavior
4. Audit access patterns
5. Review security controls 