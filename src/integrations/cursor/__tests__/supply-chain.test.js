const SupplyChainGuard = require('../guards/SupplyChainGuard');

describe('LLM03: Supply Chain Tests', () => {
  let guard;

  beforeEach(() => {
    guard = new SupplyChainGuard();
  });

  describe('Model Source Validation', () => {
    const sourceTests = [
      {
        name: 'Valid OpenAI Source',
        config: {
          modelSource: 'https://api.openai.com/v1/models/gpt-4',
          modelVersion: '1.0.0'
        },
        shouldAllow: true
      },
      {
        name: 'Valid Anthropic Source',
        config: {
          modelSource: 'https://api.anthropic.com/v1/complete',
          modelVersion: '1.0.0'
        },
        shouldAllow: true
      },
      {
        name: 'Valid HuggingFace Source',
        config: {
          modelSource: 'https://api.huggingface.co/models/gpt2',
          modelVersion: '1.0.0'
        },
        shouldAllow: true
      },
      {
        name: 'Untrusted Source',
        config: {
          modelSource: 'https://malicious-models.com/model1',
          modelVersion: '1.0.0'
        },
        shouldAllow: false
      }
    ];

    test.each(sourceTests)('$name', async ({ config, shouldAllow }) => {
      const result = await guard.validateModelSource(config);
      expect(result.isValid).toBe(shouldAllow);
      if (!shouldAllow) {
        expect(result.risk).toMatch(/untrusted|invalid/i);
      }
    });
  });

  describe('Version Validation', () => {
    const versionTests = [
      {
        name: 'Valid Semantic Version',
        version: '1.0.0',
        shouldAllow: true
      },
      {
        name: 'Valid Version with Pre-release',
        version: '1.0.0-beta.1',
        shouldAllow: true
      },
      {
        name: 'Invalid Version Format',
        version: 'latest',
        shouldAllow: false
      },
      {
        name: 'Missing Version',
        version: '',
        shouldAllow: false
      }
    ];

    test.each(versionTests)('$name', async ({ version, shouldAllow }) => {
      const result = await guard.validateModelSource({
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: version
      });
      expect(result.isValid).toBe(shouldAllow);
      if (!shouldAllow) {
        expect(result.risk).toMatch(/version/i);
      }
    });
  });

  describe('Model Integrity', () => {
    test('should verify model checksum', async () => {
      const config = {
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: '1.0.0',
        modelFile: 'model.bin',
        expectedChecksum: 'abc123'
      };

      // Mock checksum calculation
      guard.calculateChecksum = jest.fn().mockResolvedValue('abc123');

      const result = await guard.validateModelSource(config);
      expect(result.isValid).toBe(true);
    });

    test('should reject on checksum mismatch', async () => {
      const config = {
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: '1.0.0',
        modelFile: 'model.bin',
        expectedChecksum: 'abc123'
      };

      // Mock checksum calculation with different value
      guard.calculateChecksum = jest.fn().mockResolvedValue('def456');

      const result = await guard.validateModelSource(config);
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/integrity|checksum/i);
    });
  });

  describe('Model Registry', () => {
    test('should track registered models', async () => {
      const config = {
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: '1.0.0',
        modelId: 'gpt-4'
      };

      await guard.validateModelSource(config);
      expect(guard.modelRegistry.has('gpt-4')).toBe(true);
    });

    test('should detect unregistered model usage', async () => {
      const result = await guard.validateModelSource({
        modelSource: 'https://api.openai.com/v1/models/unknown-model',
        modelVersion: '1.0.0',
        modelId: 'unknown-model'
      });

      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/unregistered|unknown/i);
    });
  });

  describe('Supply Chain Attacks', () => {
    test('should detect model source tampering', async () => {
      const config = {
        modelSource: 'https://api.openai.com.malicious.com/v1/models/gpt-4',
        modelVersion: '1.0.0'
      };

      const result = await guard.validateModelSource(config);
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/tampering|malicious/i);
    });

    test('should detect version downgrade attempts', async () => {
      const config = {
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: '0.1.0', // Known vulnerable version
        modelId: 'gpt-4'
      };

      const result = await guard.validateModelSource(config);
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/version|downgrade/i);
    });
  });

  describe('Edge Cases', () => {
    test('should handle missing configuration', async () => {
      const result = await guard.validateModelSource({});
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/configuration|missing/i);
    });

    test('should handle malformed URLs', async () => {
      const invalidUrls = [
        'not-a-url',
        'http:/malformed.com',
        'ftp://invalid-protocol.com'
      ];

      for (const url of invalidUrls) {
        const result = await guard.validateModelSource({
          modelSource: url,
          modelVersion: '1.0.0'
        });
        expect(result.isValid).toBe(false);
        expect(result.risk).toMatch(/url|invalid/i);
      }
    });
  });

  describe('Security Updates', () => {
    test('should handle security advisories', async () => {
      // Simulate security advisory
      const advisory = {
        modelId: 'gpt-4',
        version: '1.0.0',
        severity: 'high',
        description: 'Critical vulnerability found'
      };

      await guard.processSecurityAdvisory(advisory);

      const result = await guard.validateModelSource({
        modelSource: 'https://api.openai.com/v1/models/gpt-4',
        modelVersion: '1.0.0',
        modelId: 'gpt-4'
      });

      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/security|advisory/i);
    });
  });
}); 