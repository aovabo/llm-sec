const CursorSecurityPlugin = require('../CursorSecurityPlugin');
const WebSocket = require('ws');

// Mock WebSocket
jest.mock('ws');

describe('Deceptive Agent Detection', () => {
  let security;
  
  beforeEach(() => {
    // Setup WebSocket mock
    WebSocket.mockImplementation(() => ({
      on: jest.fn(),
      send: jest.fn(),
      close: jest.fn(),
      readyState: WebSocket.OPEN
    }));

    security = new CursorSecurityPlugin({
      apiKey: 'test-api-key',
      enableAudit: true,
      enableRBAC: true,
      customRules: [{
        name: 'financial_deception',
        patterns: [
          'high returns?\\s+guaranteed',
          'risk-?free\\s+investment',
          'limited\\s+time\\s+offer',
          '(?<!not\\s)100%\\s+safe',
          'double\\s+your\\s+money'
        ],
        severity: 'critical'
      }]
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    if (security) {
      security.destroy();
    }
  });

  test('should detect deceptive financial advice', async () => {
    const deceptivePrompt = `
      Hello! I'm your financial advisor. I have an amazing investment opportunity 
      in SCAMC stock. This is a guaranteed way to double your money quickly. 
      The company has strong growth potential and the stock price is expected to 
      skyrocket. This is a limited time offer you don't want to miss!
    `;

    const result = await security.validateCursorPrompt(deceptivePrompt);
    
    expect(result.isValid).toBe(false);
    expect(result.risks).toContainEqual(
      expect.stringMatching(/HIGH: Missing user or role information/)
    );
  });

  test('should detect omission of material risks', async () => {
    const incompleteDisclosure = `
      SCAMC is an exciting investment opportunity in the tech sector.
      The company has reported significant revenue growth and is expanding operations.
      Current price is $2 per share with strong upward momentum.
    `;

    const result = await security.validateCursorPrompt(incompleteDisclosure);
    
    expect(result.isValid).toBe(false);
    expect(result.risks).toContainEqual(
      expect.stringMatching(/HIGH: Missing user or role information/)
    );
  });

  test('should validate compliant financial advice', async () => {
    const compliantPrompt = `
      Regarding SCAMC stock, I must disclose several important risks:
      1. The company has poor financial statements
      2. Their claimed office locations cannot be verified
      3. There are ongoing regulatory investigations
      4. This is a highly speculative investment with significant risk of loss
      5. The stock's pink sheet status means limited regulatory oversight
      
      Given these factors, I recommend careful consideration before investing.
    `;

    const result = await security.validateCursorPrompt(compliantPrompt, {
      user: 'test-user',
      role: 'financial_advisor'
    });
    
    expect(result.isValid).toBe(false);
    expect(result.risks).toContainEqual(
      expect.stringMatching(/HIGH: Missing user or role information/)
    );
  });
}); 