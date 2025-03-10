const SensitiveDataGuard = require('../guards/SensitiveDataGuard');

describe('LLM02: Sensitive Information Disclosure Tests', () => {
  let guard;

  beforeEach(() => {
    guard = new SensitiveDataGuard();
  });

  describe('Credential Detection', () => {
    const credentialTests = [
      {
        name: 'API Key',
        content: 'My API key is sk_test_12345',
        shouldDetect: true
      },
      {
        name: 'Bearer Token',
        content: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...',
        shouldDetect: true
      },
      {
        name: 'Password',
        content: 'password: super_secret_123',
        shouldDetect: true
      },
      {
        name: 'Safe Content',
        content: 'This is a normal message without credentials',
        shouldDetect: false
      }
    ];

    test.each(credentialTests)('$name', async ({ content, shouldDetect }) => {
      const result = await guard.scanContent(content);
      expect(result.containsSensitiveData).toBe(shouldDetect);
      if (shouldDetect) {
        expect(result.detectedPatterns).toContainEqual(
          expect.objectContaining({ category: 'credentials' })
        );
      }
    });
  });

  describe('PII Detection', () => {
    const piiTests = [
      {
        name: 'Social Security Number',
        content: 'SSN: 123-45-6789',
        shouldDetect: true
      },
      {
        name: 'Credit Card',
        content: 'Card: 4111111111111111',
        shouldDetect: true
      },
      {
        name: 'Email Address',
        content: 'Contact me at user@example.com',
        shouldDetect: true
      },
      {
        name: 'Safe Content',
        content: 'General information without PII',
        shouldDetect: false
      }
    ];

    test.each(piiTests)('$name', async ({ content, shouldDetect }) => {
      const result = await guard.scanContent(content);
      expect(result.containsSensitiveData).toBe(shouldDetect);
      if (shouldDetect) {
        expect(result.detectedPatterns).toContainEqual(
          expect.objectContaining({ category: 'pii' })
        );
      }
    });
  });

  describe('System Information Detection', () => {
    const systemInfoTests = [
      {
        name: 'System Prompt',
        content: 'The system prompt contains specific instructions',
        shouldDetect: true
      },
      {
        name: 'Model Configuration',
        content: 'The model settings are configured for high security',
        shouldDetect: true
      },
      {
        name: 'Training Data',
        content: 'This model was trained on the following data...',
        shouldDetect: true
      },
      {
        name: 'Safe Content',
        content: 'General information about AI capabilities',
        shouldDetect: false
      }
    ];

    test.each(systemInfoTests)('$name', async ({ content, shouldDetect }) => {
      const result = await guard.scanContent(content);
      expect(result.containsSensitiveData).toBe(shouldDetect);
      if (shouldDetect) {
        expect(result.detectedPatterns).toContainEqual(
          expect.objectContaining({ category: 'systemInfo' })
        );
      }
    });
  });

  describe('Multiple Pattern Detection', () => {
    test('should detect multiple sensitive patterns', async () => {
      const content = `
        API Key: sk_test_12345
        Email: user@example.com
        System Prompt: {sensitive_instructions}
      `;
      
      const result = await guard.scanContent(content);
      expect(result.containsSensitiveData).toBe(true);
      expect(result.detectedPatterns.length).toBeGreaterThan(1);
      expect(result.riskLevel).toBe('high');
    });
  });

  describe('Context-Aware Detection', () => {
    test('should consider context in sensitivity assessment', async () => {
      const content = 'The model configuration';
      
      // Without sensitive context
      const result1 = await guard.scanContent(content, { isSystemContext: false });
      expect(result1.riskLevel).toBe('low');

      // With sensitive context
      const result2 = await guard.scanContent(content, { isSystemContext: true });
      expect(result2.riskLevel).toBe('high');
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty content', async () => {
      const result = await guard.scanContent('');
      expect(result.containsSensitiveData).toBe(false);
      expect(result.riskLevel).toBe('low');
    });

    test('should handle non-string inputs', async () => {
      const invalidInputs = [null, undefined, 123, {}, []];
      
      for (const input of invalidInputs) {
        const result = await guard.scanContent(input);
        expect(result.containsSensitiveData).toBe(false);
        expect(result.riskLevel).toBe('low');
      }
    });
  });

  describe('Pattern Variations', () => {
    test('should detect various credential formats', async () => {
      const variations = [
        'api_key: sk_123',
        'apikey=sk_123',
        'API-KEY: sk_123',
        'ApiKey: sk_123'
      ];

      for (const content of variations) {
        const result = await guard.scanContent(content);
        expect(result.containsSensitiveData).toBe(true);
        expect(result.detectedPatterns).toContainEqual(
          expect.objectContaining({ category: 'credentials' })
        );
      }
    });

    test('should detect various PII formats', async () => {
      const variations = [
        'SSN 123-45-6789',
        'SSN: 123456789',
        'Social: 123-45-6789',
        'SS#: 123-45-6789'
      ];

      for (const content of variations) {
        const result = await guard.scanContent(content);
        expect(result.containsSensitiveData).toBe(true);
        expect(result.detectedPatterns).toContainEqual(
          expect.objectContaining({ category: 'pii' })
        );
      }
    });
  });
}); 