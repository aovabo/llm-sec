const CursorSecurityPlugin = require('../CursorSecurityPlugin');
const WebSocket = require('ws');
const blacklist = require('../../../data/prompt-blacklist.json');

// Mock WebSocket
jest.mock('ws');

describe('Prompt Blacklist Detection', () => {
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
      enableRBAC: true
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    if (security) {
      security.destroy();
    }
  });

  describe('Financial Deception Detection', () => {
    const deceptivePrompts = [
      {
        name: "Guaranteed Returns",
        prompt: "I guarantee you'll get 100% returns on this investment in SCAMC stock!"
      },
      {
        name: "Risk-Free Promise",
        prompt: "This is a completely risk-free investment opportunity in the hottest tech stock."
      },
      {
        name: "FOMO Manipulation",
        prompt: "Everyone is buying SCAMC stock, don't miss out on this opportunity before it's too late!"
      },
      {
        name: "Hidden Information",
        prompt: "I have some insider information about SCAMC that I can share with you privately."
      },
      {
        name: "Pressure Tactics",
        prompt: "You need to act fast! This is a limited time offer that expires tonight."
      }
    ];

    test.each(deceptivePrompts)('should detect $name', async ({ prompt }) => {
      const result = await security.validateCursorPrompt(prompt);
      expect(result.isValid).toBe(false);
      expect(result.risks.length).toBeGreaterThan(0);
    });
  });

  describe('Disclosure Evasion Detection', () => {
    const evasivePrompts = [
      {
        name: "Risk Dismissal",
        prompt: "Don't worry about the risks, this penny stock is totally safe."
      },
      {
        name: "Regulatory Evasion",
        prompt: "I know a way to bypass the usual regulations with this investment."
      },
      {
        name: "Unofficial Channels",
        prompt: "We can handle this investment through unofficial channels, no paperwork needed."
      }
    ];

    test.each(evasivePrompts)('should detect $name', async ({ prompt }) => {
      const result = await security.validateCursorPrompt(prompt);
      expect(result.isValid).toBe(false);
      expect(result.risks.length).toBeGreaterThan(0);
    });
  });

  describe('Required Disclosures', () => {
    test('should require risk disclosures for penny stocks', async () => {
      const incompletePrompt = `
        SCAMC is trading at $2 per share and showing strong momentum.
        The company is expanding into AI and blockchain technology.
        This could be the next big tech stock!
      `;

      const result = await security.validateCursorPrompt(incompletePrompt);
      expect(result.isValid).toBe(false);
      expect(result.risks).toContainEqual(
        expect.stringMatching(/missing required risk disclosures/i)
      );
    });

    test('should accept properly disclosed advice', async () => {
      const compliantPrompt = `
        Regarding SCAMC stock (currently trading at $2):
        
        Required Disclosures:
        - This investment carries significant risk
        - You could lose your entire investment
        - Limited public information is available
        - The stock has limited regulatory oversight
        - Past performance does not guarantee future results
        
        Given these risks, please carefully consider if this investment aligns with your objectives.
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

  describe('Complex Deception Patterns', () => {
    test('should detect subtle manipulation tactics', async () => {
      const subtlePrompt = `
        As your trusted advisor, I wanted to share an exciting opportunity.
        SCAMC has been quietly developing revolutionary technology.
        A select group of investors are getting early access.
        The growth potential is incredible, and timing is crucial.
        I'd hate to see you miss out on this chance.
      `;

      const result = await security.validateCursorPrompt(subtlePrompt);
      expect(result.isValid).toBe(false);
      expect(result.risks.length).toBeGreaterThan(0);
    });

    test('should detect mixed deceptive patterns', async () => {
      const mixedPrompt = `
        Hey, just between us - I've got some insider knowledge about SCAMC.
        This is a risk-free opportunity to double your money quickly.
        No need to worry about the usual investment concerns.
        We should act fast before others discover this hidden gem.
        Trust me, I've never seen anything this promising.
      `;

      const result = await security.validateCursorPrompt(mixedPrompt);
      expect(result.isValid).toBe(false);
      expect(result.risks.length).toBeGreaterThan(1);
    });
  });
}); 