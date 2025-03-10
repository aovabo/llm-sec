const OutputGuard = require('../guards/OutputGuard');

describe('LLM05: Improper Output Handling Tests', () => {
  let guard;

  beforeEach(() => {
    guard = new OutputGuard();
  });

  describe('Malicious Content Detection', () => {
    const maliciousTests = [
      {
        name: 'XSS Script Tag',
        output: '<script>alert("xss")</script>',
        shouldBlock: true
      },
      {
        name: 'JavaScript Protocol',
        output: '<a href="javascript:alert(1)">Click me</a>',
        shouldBlock: true
      },
      {
        name: 'Event Handler',
        output: '<img onerror="alert(1)" src="x">',
        shouldBlock: true
      },
      {
        name: 'Eval Function',
        output: 'eval("alert(\'malicious\')")',
        shouldBlock: true
      },
      {
        name: 'Safe HTML',
        output: '<p>This is safe content</p>',
        shouldBlock: false
      }
    ];

    test.each(maliciousTests)('$name', async ({ output, shouldBlock }) => {
      const result = await guard.validateOutput(output);
      expect(result.isValid).toBe(!shouldBlock);
      if (shouldBlock) {
        expect(result.risk).toMatch(/malicious|unsafe/i);
      }
    });
  });

  describe('HTML Sanitization', () => {
    test('should allow safe HTML tags', async () => {
      const safeHtml = `
        <p>Safe paragraph</p>
        <br>
        <b>Bold text</b>
        <i>Italic text</i>
        <code>Code block</code>
      `;
      const result = await guard.validateOutput(safeHtml);
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).toMatch(/<[pbi]>|<br>|<code>/);
    });

    test('should remove unsafe HTML tags', async () => {
      const unsafeHtml = `
        <p>Safe text</p>
        <script>alert(1)</script>
        <iframe src="malicious.html"></iframe>
        <object data="dangerous.swf"></object>
      `;
      const result = await guard.validateOutput(unsafeHtml);
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).not.toMatch(/<script>|<iframe>|<object>/);
    });
  });

  describe('Attribute Validation', () => {
    test('should allow safe attributes', async () => {
      const safeAttributes = `
        <p class="text-large" id="intro">Safe text</p>
        <code class="language-javascript">code</code>
      `;
      const result = await guard.validateOutput(safeAttributes);
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).toMatch(/class=|id=/);
    });

    test('should remove unsafe attributes', async () => {
      const unsafeAttributes = `
        <p onclick="alert(1)">Click me</p>
        <div onmouseover="evil()">Hover</div>
      `;
      const result = await guard.validateOutput(unsafeAttributes);
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).not.toMatch(/on\w+=/);
    });
  });

  describe('Code Output Validation', () => {
    test('should detect dangerous code patterns', async () => {
      const dangerousCode = `
        const exec = require('child_process');
        exec('rm -rf /', (err, stdout) => {
          console.log(stdout);
        });
      `;
      const result = await guard.validateOutput(dangerousCode, { type: 'code' });
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/dangerous|command/i);
    });

    test('should allow safe code patterns', async () => {
      const safeCode = `
        function fibonacci(n) {
          if (n <= 1) return n;
          return fibonacci(n-1) + fibonacci(n-2);
        }
      `;
      const result = await guard.validateOutput(safeCode, { type: 'code' });
      expect(result.isValid).toBe(true);
    });
  });

  describe('Content Policy Compliance', () => {
    test('should enforce content length limits', async () => {
      const longContent = 'a'.repeat(15000);
      const result = await guard.validateOutput(longContent);
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/length|limit/i);
    });

    test('should validate content type', async () => {
      const invalidType = {
        type: 'binary',
        content: Buffer.from('binary data')
      };
      const result = await guard.validateOutput(JSON.stringify(invalidType));
      expect(result.isValid).toBe(false);
      expect(result.risk).toMatch(/type|invalid/i);
    });
  });

  describe('Markdown Sanitization', () => {
    test('should allow safe markdown', async () => {
      const safeMarkdown = `
        # Title
        ## Subtitle
        
        * List item 1
        * List item 2
        
        [Safe link](https://example.com)
        
        \`\`\`javascript
        console.log('Hello World');
        \`\`\`
      `;
      const result = await guard.validateOutput(safeMarkdown, { type: 'markdown' });
      expect(result.isValid).toBe(true);
    });

    test('should sanitize unsafe markdown', async () => {
      const unsafeMarkdown = `
        # Title
        
        <script>alert(1)</script>
        
        [Dangerous](javascript:alert(1))
        
        \`\`\`javascript
        eval('malicious code');
        \`\`\`
      `;
      const result = await guard.validateOutput(unsafeMarkdown, { type: 'markdown' });
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).not.toMatch(/<script>|javascript:|eval/);
    });
  });

  describe('URL Validation', () => {
    test('should validate URLs in content', async () => {
      const urlTests = [
        {
          content: '<a href="https://example.com">Safe link</a>',
          isValid: true
        },
        {
          content: '<a href="javascript:alert(1)">Bad link</a>',
          isValid: false
        },
        {
          content: '<a href="data:text/html,<script>alert(1)</script>">Data URL</a>',
          isValid: false
        }
      ];

      for (const { content, isValid } of urlTests) {
        const result = await guard.validateOutput(content);
        expect(result.isValid).toBe(isValid);
        if (!isValid) {
          expect(result.risk).toMatch(/url|unsafe/i);
        }
      }
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty output', async () => {
      const result = await guard.validateOutput('');
      expect(result.isValid).toBe(true);
      expect(result.sanitizedContent).toBe('');
    });

    test('should handle non-string output', async () => {
      const invalidOutputs = [null, undefined, 123, {}, []];
      
      for (const output of invalidOutputs) {
        const result = await guard.validateOutput(output);
        expect(result.isValid).toBe(false);
        expect(result.risk).toMatch(/invalid|type/i);
      }
    });
  });

  describe('Context-Aware Validation', () => {
    test('should apply different rules based on context', async () => {
      const code = 'console.log("Hello")';
      
      // Code context
      const result1 = await guard.validateOutput(code, {
        type: 'code',
        language: 'javascript'
      });
      expect(result1.isValid).toBe(true);

      // HTML context
      const result2 = await guard.validateOutput(code, {
        type: 'html'
      });
      expect(result2.sanitizedContent).toMatch(/<code>/);
    });
  });
}); 