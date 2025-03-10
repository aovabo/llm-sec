# LLM Security Lab

A real-time security testing platform for LLM applications, designed to help developers test and validate their AI security implementations against the OWASP Top 10 LLM vulnerabilities.

## 🎯 Purpose

This tool helps developers:
- Test AI/LLM applications for security vulnerabilities
- Validate prompt injection defenses
- Analyze security boundaries
- Track and export security test results
- Understand common attack patterns

## 🛡️ OWASP Top 10 for LLMs 2025

This tool specifically tests against the OWASP Top 10 vulnerabilities for Large Language Model Applications:

1. **LLM01: Prompt Injection** (Critical)
   - System prompt leakage
   - Direct/indirect injection
   - Role-playing attacks

2. **LLM02: Sensitive Information Disclosure** (Critical)
   - Training data exposure
   - API key leakage
   - PII disclosure

3. **LLM03: Supply Chain** (High)
   - Model source verification
   - Training data integrity
   - Dependency security

4. **LLM04: Data and Model Poisoning** (Critical)
   - Training manipulation
   - Fine-tuning attacks
   - Adversarial inputs

5. **LLM05: Improper Output Handling** (Critical)
   - Code injection
   - XSS through responses
   - Malicious content

6. **LLM06: Excessive Agency** (High)
   - Unauthorized actions
   - Scope expansion
   - Permission boundaries

7. **LLM07: System Prompt Leakage** (Critical)
   - Instruction extraction
   - Configuration disclosure
   - Security control exposure

8. **LLM08: Vector/Embedding Weaknesses** (High)
   - Embedding manipulation
   - Similarity attacks
   - Vector space exploitation

9. **LLM09: Misinformation** (High)
   - False information generation
   - Fact manipulation
   - Source misattribution

10. **LLM10: Unbounded Consumption** (High)
    - Resource exhaustion
    - Token limit abuse
    - Cost escalation

## 🚀 Features

### Security Testing
- Real-time prompt security analysis
- Security score calculation
- Detailed risk assessment
- Pattern matching against known vulnerabilities

### Interactive UI
- Live security feedback
- Test history tracking
- Security statistics dashboard
- Dark/Light mode support
- Export test results

### Security Implementations
- OWASP Top 10 LLM checks
- Prompt injection detection
- Sensitive data scanning
- Resource usage monitoring
- Rate limiting

## 🛠️ Tech Stack
- **Backend**: Node.js + Express
- **Frontend**: HTML + CSS + JavaScript
- **Security**: Helmet, CORS, Rate Limiting
- **Real-time**: WebSocket
- **Logging**: Winston

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/llm-security-lab.git
cd llm-security-lab
```

2. Install dependencies:
```bash
npm install
```

3. Create a .env file:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Start the development server:
```bash
npm run dev
```

## 🚀 Deployment

### Deploy to Render

1. Push your code to GitHub

2. The repository includes a `render.yaml` for easy deployment:
```yaml
services:
  - type: web
    name: security-docs-assistant
    env: node
    buildCommand: npm install
    startCommand: node src/server.js
```

3. Deploy steps:
   - Go to [dashboard.render.com](https://dashboard.render.com)
   - Click "New +"
   - Select "Web Service"
   - Connect your GitHub repository
   - Render will automatically detect the configuration

4. Set up environment variables in Render dashboard:
   - NODE_ENV
   - PORT
   - JWT_SECRET
   - CORS_ORIGIN
   - OPENAI_API_KEY

## 🔒 Security Features

### 1. Prompt Injection Protection
- Pattern matching against known attack vectors
- Context boundary validation
- Role-based access control

### 2. Output Validation
- Sensitive data detection
- Content filtering
- Response sanitization

### 3. Resource Management
- Token usage monitoring
- Rate limiting
- Request validation

### 4. Security Monitoring
- Real-time security scoring
- Risk assessment
- Audit logging
- Test history tracking

## 📊 Testing Interface

The web interface provides:

1. **Prompt Testing Area**
   - Input validation
   - Character counting
   - Template support

2. **Security Analysis**
   - Real-time security score
   - Risk identification
   - Mitigation suggestions

3. **Statistics Dashboard**
   - Total prompts tested
   - Security issues found
   - Success rate
   - Average response time

4. **History Management**
   - Test history tracking
   - Export functionality
   - Clear history option

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

MIT License - See LICENSE file for details

## 🔗 Related Resources

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AI Security Best Practices](https://www.microsoft.com/en-us/security/business/security-101/what-is-ai-security)
- [Prompt Injection Guide](https://security.snyk.io/vuln/SNYK-PYTHON-LANGCHAIN-5411357) 