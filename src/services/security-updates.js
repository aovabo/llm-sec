const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');

class SecurityUpdatesService {
  constructor() {
    this.sources = {
      owasp_llm: 'https://genai.owasp.org/llm-top-10/latest.json',
      owasp_web: 'https://owasp.org/www-project-top-10/latest.json',
      owasp_api: 'https://owasp.org/www-project-api-security/latest.json',
      mitre: 'https://attack.mitre.org/api/v1/matrices/'
    };

    this.updateIntervals = {
      owasp_llm: 24 * 60 * 60 * 1000, // Daily
      owasp_web: 24 * 60 * 60 * 1000,
      owasp_api: 24 * 60 * 60 * 1000,
      mitre: 24 * 60 * 60 * 1000
    };
  }

  async initialize() {
    // Start update checks for each source
    Object.keys(this.sources).forEach(source => {
      this.scheduleUpdates(source);
    });
  }

  scheduleUpdates(source) {
    setInterval(async () => {
      try {
        await this.checkForUpdates(source);
      } catch (error) {
        winston.error(`Error checking updates for ${source}:`, error);
      }
    }, this.updateIntervals[source]);
  }

  async checkForUpdates(source) {
    try {
      const response = await axios.get(this.sources[source], {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Security-Docs-Assistant/1.0'
        }
      });

      const newData = response.data;
      
      // Validate the new data
      if (await this.validateUpdate(source, newData)) {
        // Update local documentation
        await this.updateLocalDocs(source, newData);
        
        // Notify connected clients
        this.broadcastUpdate(source);
      }
    } catch (error) {
      winston.error(`Failed to check updates for ${source}:`, error);
    }
  }

  async validateUpdate(source, data) {
    // Implement validation logic based on source
    switch (source) {
      case 'owasp_llm':
        return this.validateOwaspLLM(data);
      case 'owasp_web':
        return this.validateOwaspWeb(data);
      case 'owasp_api':
        return this.validateOwaspAPI(data);
      case 'mitre':
        return this.validateMitre(data);
      default:
        return false;
    }
  }

  validateOwaspLLM(data) {
    // Validate OWASP LLM data structure
    return (
      data.version &&
      data.categories &&
      Array.isArray(data.categories) &&
      data.categories.length === 10 &&
      data.categories.every(category =>
        category.id &&
        category.name &&
        category.description &&
        category.impact &&
        Array.isArray(category.examples) &&
        Array.isArray(category.mitigations)
      )
    );
  }

  async updateLocalDocs(source, data) {
    const filePath = this.getLocalFilePath(source);
    
    try {
      // Backup existing file
      await this.backupFile(filePath);
      
      // Write new data
      await fs.writeFile(
        filePath,
        JSON.stringify(data, null, 2),
        'utf8'
      );

      winston.info(`Updated documentation for ${source}`);
    } catch (error) {
      winston.error(`Failed to update local docs for ${source}:`, error);
      // Restore from backup if update fails
      await this.restoreFromBackup(filePath);
    }
  }

  async backupFile(filePath) {
    const backupPath = `${filePath}.backup`;
    try {
      await fs.copyFile(filePath, backupPath);
    } catch (error) {
      winston.error(`Failed to create backup for ${filePath}:`, error);
    }
  }

  async restoreFromBackup(filePath) {
    const backupPath = `${filePath}.backup`;
    try {
      await fs.copyFile(backupPath, filePath);
      winston.info(`Restored ${filePath} from backup`);
    } catch (error) {
      winston.error(`Failed to restore from backup for ${filePath}:`, error);
    }
  }

  getLocalFilePath(source) {
    const fileNames = {
      owasp_llm: 'llm-security.json',
      owasp_web: 'owasp.json',
      owasp_api: 'api-security.json',
      mitre: 'mitre.json'
    };

    return path.join(__dirname, '..', 'data', fileNames[source]);
  }

  broadcastUpdate(source) {
    // Implement WebSocket broadcast to notify clients of updates
    global.wss?.clients?.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'SECURITY_UPDATE',
          source: source,
          timestamp: new Date().toISOString()
        }));
      }
    });
  }
}

module.exports = new SecurityUpdatesService(); 