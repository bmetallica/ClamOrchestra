import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import pg from 'pg';
import dotenv from 'dotenv';
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import { Client as SSHClient } from 'ssh2';
import fs from 'fs';
import path from 'path';
import os from 'os';

dotenv.config();

const app = express();
const { Pool } = pg;

// ============= DATABASE =============
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Email service - dynamisch aus Datenbank laden
let mailer = null;

async function initializeMailer() {
  console.log('[Mailer Init] Starting mailer initialization...');
  try {
    const settings = await pool.query(`
      SELECT setting_key, setting_value FROM system_settings 
      WHERE setting_key IN ('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_SECURE', 'SMTP_FROM')
    `);
    
    console.log('[Mailer Init] Found', settings.rows.length, 'settings in database');
    
    const settingsMap = {};
    settings.rows.forEach(row => {
      const match = row.setting_key?.match(/SMTP_(.+)/);
      if (match) {
        settingsMap[match[1]] = row.setting_value;
        console.log('[Mailer Init] Loaded DB setting:', match[1], '=', row.setting_value?.substring(0, 5) + '***');
      }
    });
    
    const port = parseInt(settingsMap['PORT']) || parseInt(process.env.SMTP_PORT) || 587;
    const isSecure = settingsMap['SECURE'] === 'true' || process.env.SMTP_SECURE === 'true';
    
    const finalConfig = {
      host: settingsMap['HOST'] || process.env.SMTP_HOST || 'localhost',
      port: port,
      secure: isSecure,
      auth: (settingsMap['USER'] || process.env.SMTP_USER) ? {
        user: settingsMap['USER'] || process.env.SMTP_USER,
        pass: settingsMap['PASSWORD'] || process.env.SMTP_PASSWORD
      } : undefined
    };
    
    // Port 25 = Plain SMTP ohne STARTTLS
    // Port 587 = SMTP mit STARTTLS
    // Port 465 = Direct TLS/SSL
    
    if (port === 25) {
      console.log('[Mailer Init] Port 25 detected: Disabling STARTTLS');
      finalConfig.ignoreTLS = true; // Deaktiviert STARTTLS für Port 25
    } else if (port === 587 || port === 25) {
      console.log('[Mailer Init] Port 587+ detected: Using STARTTLS with relaxed certificate validation');
      // Für Testnetzwerk: Zertifikats-Validierung deaktivieren (NOT for production!)
      finalConfig.tls = {
        rejectUnauthorized: false // Akzeptiert selfsigned/mismatched Zertifikate
      };
    } else if (port === 465) {
      console.log('[Mailer Init] Port 465 detected: Using Direct TLS with relaxed validation');
      finalConfig.tls = {
        rejectUnauthorized: false
      };
    }
    
    console.log('[Mailer Init] Final config:', {
      host: finalConfig.host,
      port: finalConfig.port,
      secure: finalConfig.secure,
      ignoreTLS: finalConfig.ignoreTLS || false,
      auth: finalConfig.auth ? 'Yes' : 'No',
      tlsRejectUnauth: finalConfig.tls?.rejectUnauthorized
    });
    
    mailer = nodemailer.createTransport(finalConfig);
    console.log('[Mailer Init] ✅ Mailer reinitialized successfully');
  } catch (error) {
    console.error('[Mailer] Error initializing:', error.message);
    console.log('[Mailer] Falling back to .env settings');
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'localhost',
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      } : undefined
    });
  }
}

function getMailer() {
  if (!mailer) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'localhost',
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      } : undefined
    });
  }
  return mailer;
}

// Database initialization
async function initDb() {
  const client = await pool.connect();
  try {
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Servers table
    await client.query(`
      CREATE TABLE IF NOT EXISTS servers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        hostname VARCHAR(255) UNIQUE NOT NULL,
        ip_address VARCHAR(255),
        port INTEGER DEFAULT 22,
        ssh_user VARCHAR(255) DEFAULT 'root',
        description TEXT,
        status VARCHAR(50) DEFAULT 'offline',
        last_check TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Add ssh_user column if it doesn't exist
    await client.query(`
      ALTER TABLE servers 
      ADD COLUMN IF NOT EXISTS ssh_user VARCHAR(255) DEFAULT 'root';
    `);

    // Add signature_updated_at column if it doesn't exist
    await client.query(`
      ALTER TABLE servers 
      ADD COLUMN IF NOT EXISTS signature_updated_at TIMESTAMP;
    `);

    // SSH Keys table
    await client.query(`
      CREATE TABLE IF NOT EXISTS ssh_keys (
        id SERIAL PRIMARY KEY,
        key_name VARCHAR(255) NOT NULL,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        ssh_user VARCHAR(255) DEFAULT 'clam',
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ClamAV Config table
    await client.query(`
      CREATE TABLE IF NOT EXISTS clamav_configs (
        id SERIAL PRIMARY KEY,
        server_id INTEGER UNIQUE REFERENCES servers(id),
        version VARCHAR(255),
        is_installed BOOLEAN DEFAULT FALSE,
        freshclam_enabled BOOLEAN DEFAULT TRUE,
        clamd_enabled BOOLEAN DEFAULT TRUE,
        config_path VARCHAR(255) DEFAULT '/etc/clamav/clamd.conf',
        freshclam_config VARCHAR(255) DEFAULT '/etc/clamav/freshclam.conf',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Migration: Add updated_at column if missing
    await client.query(`
      ALTER TABLE clamav_configs 
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    `);

    // Scan jobs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS scan_jobs (
        id SERIAL PRIMARY KEY,
        server_id INTEGER REFERENCES servers(id),
        name VARCHAR(255) NOT NULL,
        scan_type VARCHAR(50) DEFAULT 'quick',
        paths TEXT[] DEFAULT ARRAY['/home']::text[],
        cron_expression VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        last_run TIMESTAMP,
        next_run TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Scan results table
    await client.query(`
      CREATE TABLE IF NOT EXISTS scan_results (
        id SERIAL PRIMARY KEY,
        server_id INTEGER REFERENCES servers(id),
        scan_job_id INTEGER REFERENCES scan_jobs(id),
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP,
        status VARCHAR(50) DEFAULT 'running',
        files_scanned INTEGER DEFAULT 0,
        threats_found INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Detections table
    await client.query(`
      CREATE TABLE IF NOT EXISTS detections (
        id SERIAL PRIMARY KEY,
        scan_result_id INTEGER REFERENCES scan_results(id),
        server_id INTEGER REFERENCES servers(id),
        file_path TEXT,
        threat_name VARCHAR(255),
        severity VARCHAR(50) DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP DEFAULT NULL
      );
    `);

    // Alerts table
    await client.query(`
      CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        server_id INTEGER REFERENCES servers(id),
        detection_id INTEGER REFERENCES detections(id),
        alert_type VARCHAR(50),
        message TEXT DEFAULT '',
        is_sent BOOLEAN DEFAULT FALSE,
        sent_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Log fetch schedules table
    await client.query(`
      CREATE TABLE IF NOT EXISTS log_fetch_schedules (
        id SERIAL PRIMARY KEY,
        server_id INTEGER UNIQUE REFERENCES servers(id),
        frequency VARCHAR(50) DEFAULT 'hourly',
        daily_hour INTEGER DEFAULT 0,
        weekly_day INTEGER DEFAULT 0,
        weekly_hour INTEGER DEFAULT 0,
        enabled BOOLEAN DEFAULT TRUE,
        last_fetch TIMESTAMP,
        log_path VARCHAR(255) DEFAULT '/var/log/clamav/clamd.log',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Detected remote cronjobs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS detected_cronjobs (
        id SERIAL PRIMARY KEY,
        server_id INTEGER REFERENCES servers(id),
        scan_job_id INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
        cron_expression VARCHAR(255),
        command TEXT,
        status VARCHAR(50) DEFAULT 'active',
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(server_id, cron_expression, command)
      );
    `);

    // System settings table
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(255) UNIQUE NOT NULL,
        setting_value TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Database migrations for existing tables
    await client.query(`ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_user VARCHAR(255) DEFAULT 'root'`);
    await client.query(`ALTER TABLE detected_cronjobs ADD COLUMN IF NOT EXISTS scan_job_id INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL`);
    await client.query(`ALTER TABLE log_fetch_schedules ADD COLUMN IF NOT EXISTS frequency VARCHAR(50) DEFAULT 'hourly'`);
    await client.query(`ALTER TABLE log_fetch_schedules ADD COLUMN IF NOT EXISTS daily_hour INTEGER DEFAULT 0`);
    await client.query(`ALTER TABLE log_fetch_schedules ADD COLUMN IF NOT EXISTS weekly_day INTEGER DEFAULT 0`);
    await client.query(`ALTER TABLE log_fetch_schedules ADD COLUMN IF NOT EXISTS weekly_hour INTEGER DEFAULT 0`);
    await client.query(`ALTER TABLE log_fetch_schedules ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE`);
    await client.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS message TEXT DEFAULT ''`);
    await client.query(`ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS raw_output TEXT`);
    
    // Rename system_settings columns to match code
    await client.query(`ALTER TABLE system_settings RENAME COLUMN key TO setting_key`).catch(() => {});
    await client.query(`ALTER TABLE system_settings RENAME COLUMN value TO setting_value`).catch(() => {});
    await client.query(`ALTER TABLE system_settings DROP COLUMN IF EXISTS data_type`).catch(() => {});
    
    // Add threats_found if it doesn't exist (in case table was created with infections_found)
    try {
      await client.query(`ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS threats_found INTEGER DEFAULT 0`);
      // If infections_found exists but threats_found doesn't, copy the data
      const result = await client.query("SELECT column_name FROM information_schema.columns WHERE table_name='scan_results' AND column_name='infections_found'");
      if (result.rows.length > 0) {
        // Copy infections_found to threats_found if threats_found is empty
        await client.query(`UPDATE scan_results SET threats_found = infections_found WHERE threats_found = 0 AND infections_found > 0`);
      }
    } catch (e) {
      // Column might already exist, that's fine
    }

    // Add resolved_at column to detections table if it doesn't exist
    await client.query(`ALTER TABLE detections ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP DEFAULT NULL`);

    // Create default admin user if not exists
    const adminCheck = await client.query('SELECT id FROM users WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hash = await bcryptjs.hash('admin', 10);
      await client.query(
        'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4)',
        ['admin', 'admin@clamorchestra.local', hash, true]
      );
      console.log('✅ Admin user created: admin / admin');
    }

    console.log('✅ Database initialized');
    
    // Initialize mailer with DB settings
    await initializeMailer();
    
    // Initialize log fetch scheduler
    initializeLogFetchScheduler();
  } catch (error) {
    console.error('❌ Database error:', error.message);
  } finally {
    client.release();
  }
}

// ============= ALERT EMAIL SENDER =============
async function sendPendingAlerts() {
  try {
    console.log('[AlertEmailSender] Fetching unsent alerts...');
    
    // First, check how many unsent alerts exist in total
    const totalRes = await pool.query(`SELECT COUNT(*) as count FROM alerts WHERE is_sent = FALSE`);
    console.log(`[AlertEmailSender] Total unsent alerts in DB: ${totalRes.rows[0].count}`);
    
    // Get all unsent alerts with related data (more robust query)
    const result = await pool.query(`
      SELECT a.id, a.server_id, a.detection_id, a.message, a.created_at,
             COALESCE(s.name, 'Unknown Server') as server_name,
             d.threat_name, d.file_path, d.severity, d.scan_result_id,
             sr.start_time as scan_time
      FROM alerts a
      LEFT JOIN servers s ON a.server_id = s.id
      LEFT JOIN detections d ON a.detection_id = d.id
      LEFT JOIN scan_results sr ON d.scan_result_id = sr.id
      WHERE a.is_sent = FALSE
      ORDER BY a.created_at DESC
    `);
    
    console.log(`[AlertEmailSender] Query returned ${result.rows.length} alerts`);
    
    if (result.rows.length > 0) {
      result.rows.forEach((row, idx) => {
        console.log(`[AlertEmailSender] Alert ${idx+1}: id=${row.id}, server_id=${row.server_id}, server_name=${row.server_name}, threat=${row.threat_name}`);
      });
    }
    
    if (result.rows.length === 0) {
      console.log('[AlertEmailSender] No unsent alerts found');
      return;
    }
    
    console.log(`[AlertEmailSender] Found ${result.rows.length} unsent alerts`);
    
    // Get admin email from database or use default
    const adminEmailRes = await pool.query(`
      SELECT setting_value FROM system_settings WHERE setting_key = 'ALERT_EMAIL_TO'
    `).catch(() => ({ rows: [] }));
    
    const adminEmail = adminEmailRes.rows?.[0]?.setting_value || 'admin@clamorchestra.local';
    console.log('[AlertEmailSender] Sending alerts to:', adminEmail);
    
    // Group alerts by creation date for better readability
    const alertsByDate = {};
    result.rows.forEach(alert => {
      const dateKey = new Date(alert.created_at).toLocaleDateString('de-DE');
      if (!alertsByDate[dateKey]) alertsByDate[dateKey] = [];
      alertsByDate[dateKey].push(alert);
    });
    
    // Build email HTML
    let alertCount = result.rows.length;
    let emailBody = `
      <h2>🚨 ClamOrchestra - Bedrohungen erkannt</h2>
      <p>Es wurden <strong>${alertCount} neue Bedrohung(en)</strong> in den letzten Stunden erkannt.</p>
      
      <hr style="margin: 20px 0;">
    `;
    
    Object.entries(alertsByDate).forEach(([date, alerts]) => {
      emailBody += `<h3>📅 ${date} (${alerts.length} Alert${alerts.length > 1 ? 's' : ''})</h3>`;
      emailBody += '<ul style="list-style: none; padding: 0;">';
      
      alerts.forEach(alert => {
        const severityColor = alert.severity === 'high' ? '#dc3545' : alert.severity === 'medium' ? '#ff9800' : '#28a745';
        const threatDisplay = alert.threat_name || 'Unknown Threat';
        const fileDisplay = alert.file_path || 'Unknown File';
        
        emailBody += `
          <li style="margin: 15px 0; padding: 15px; background: #f5f5f5; border-left: 4px solid ${severityColor}; border-radius: 4px;">
            <strong>Server:</strong> ${alert.server_name}<br/>
            <strong>Threat:</strong> <span style="color: ${severityColor}; font-weight: bold;">${threatDisplay}</span><br/>
            <strong>Severity:</strong> <span style="color: ${severityColor};">${(alert.severity || 'unknown').toUpperCase()}</span><br/>
            <strong>File:</strong> <code>${fileDisplay}</code><br/>
            <strong>Scan Time:</strong> ${alert.scan_time ? new Date(alert.scan_time).toLocaleString('de-DE') : 'Unknown'}<br/>
            <strong>Message:</strong> ${alert.message || 'No message'}
          </li>
        `;
      });
      
      emailBody += '</ul>';
    });
    
    emailBody += `
      <hr style="margin: 20px 0;">
      <p style="color: #666; font-size: 12px;">
        Sent by ClamOrchestra at ${new Date().toLocaleString('de-DE')}<br/>
        <a href="http://localhost:3000/alerts">📊 View all alerts in dashboard</a>
      </p>
    `;
    
    // Send email
    const mailerInstance = getMailer();
    const fromEmail = (await pool.query(`
      SELECT setting_value FROM system_settings WHERE setting_key = 'SMTP_FROM'
    `).catch(() => ({ rows: [{ setting_value: 'noreply@clamorchestra.local' }] }))).rows[0]?.setting_value || 'noreply@clamorchestra.local';
    
    const mailOptions = {
      from: fromEmail,
      to: adminEmail,
      subject: `🚨 ClamOrchestra Alert: ${alertCount} Threat${alertCount > 1 ? 's' : ''} Detected`,
      html: emailBody
    };
    
    console.log('[AlertEmailSender] Sending email to', adminEmail);
    const sendResult = await mailerInstance.sendMail(mailOptions);
    console.log('[AlertEmailSender] ✅ Email sent successfully!');
    console.log('[AlertEmailSender]   Response ID:', sendResult.response?.substring(0, 50));
    console.log('[AlertEmailSender]   Message ID:', sendResult.messageId);
    
    // Mark all alerts as sent
    const updateResult = await pool.query(
      `UPDATE alerts SET is_sent = TRUE, sent_at = NOW() WHERE is_sent = FALSE`
    );
    
    console.log(`[AlertEmailSender] ✅ Marked ${updateResult.rowCount} alerts as sent`);
    
  } catch (error) {
    console.error('[AlertEmailSender] ❌ Error sending alerts:', error.message);
    console.error('[AlertEmailSender]', error);
  }
}

// ============= LOG FETCH SCHEDULER =============
async function initializeLogFetchScheduler() {
  console.log('[LogFetcher] Initializing log fetch scheduler...');
  
  // Load all servers and their fetch schedules on startup
  const schedules = await pool.query('SELECT * FROM log_fetch_schedules WHERE enabled = TRUE');
  
  for (const schedule of schedules.rows) {
    setupScheduleForServer(schedule);
  }
}

function setupScheduleForServer(schedule) {
  const server_id = schedule.server_id;
  const frequency = schedule.frequency || 'hourly';
  let cronExpression;
  
  // Map frequency to cron expression
  if (frequency === 'hourly') {
    cronExpression = '0 * * * *'; // Every hour at minute 0
  } else if (frequency === 'daily') {
    const hour = schedule.daily_hour || 0;
    cronExpression = `0 ${hour} * * *`; // Daily at specific hour
  } else if (frequency === 'weekly') {
    const day = schedule.weekly_day || 0; // 0 = Sunday
    const hour = schedule.weekly_hour || 0;
    cronExpression = `0 ${hour} * * ${day}`; // Weekly at specific day/hour
  } else {
    cronExpression = '0 * * * *'; // Default hourly
  }
  
  console.log(`[LogFetcher] Scheduling server ${server_id}: ${frequency} (${cronExpression})`);
  
  // Setup cron job for this server
  cron.schedule(cronExpression, async () => {
    console.log(`[LogFetcher] Starting log fetch for server ${server_id}`);
    await fetchServerLogs(server_id);
  });
}

async function fetchServerLogs(serverId) {
  try {
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
    if (serverRes.rows.length === 0) {
      console.error(`[LogFetcher] Server ${serverId} not found`);
      return;
    }
    
    const server = serverRes.rows[0];
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    if (keyRes.rows.length === 0) {
      console.error('[LogFetcher] No default SSH key configured');
      return;
    }
    
    const key = keyRes.rows[0];
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    return new Promise((resolve) => {
      const ssh = new SSHClient();
      
      ssh.on('ready', () => {
        const commands = [
          `sudo ls -la /var/log/clamav`,
          `sudo tail -n 100 /var/log/clamav/clamav.log 2>/dev/null || echo "No clamav log"`,
          `sudo tail -n 100 /var/log/clamav/freshclam.log 2>/dev/null || echo "No freshclam log"`,
          `crontab -l 2>/dev/null || echo "No user cronjobs"`,
          `sudo cat /etc/cron.d/clamorchestra-scans 2>/dev/null || echo "No system cronjobs"`,
          `stat -c %y /var/lib/clamav/main.cvd 2>/dev/null || echo "Unknown"`,
          `sudo find /var/log/clamav -name 'scan_*.log' -type f | sort -V | tail -3`,
          `which clamscan && clamscan --version 2>/dev/null | head -1 || echo "Not installed"`
        ];
        
        executeCommands(ssh, commands, async (results) => {
          // Check if ClamAV is installed
          const clamavCheckOutput = (results.command_7 || '').toString().trim();
          const isClamavInstalled = clamavCheckOutput !== '' && !clamavCheckOutput.includes('Not installed');
          
          // Update clamav_configs with installation status
          if (isClamavInstalled) {
            const versionMatch = clamavCheckOutput.match(/ClamAV ([^\s/]+)/i);
            const version = versionMatch ? versionMatch[1] : null;
            await pool.query(
              'INSERT INTO clamav_configs (server_id, is_installed, version, updated_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (server_id) DO UPDATE SET is_installed = $2, version = $3, updated_at = NOW()',
              [serverId, true, version]
            ).catch(e => console.error('[LogFetcher] Error updating ClamAV status:', e.message));
            console.log(`[LogFetcher] ClamAV is installed on server ${serverId} (version: ${version})`);
          } else {
            await pool.query(
              'INSERT INTO clamav_configs (server_id, is_installed, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (server_id) DO UPDATE SET is_installed = $2, updated_at = NOW()',
              [serverId, false]
            ).catch(e => console.error('[LogFetcher] Error updating ClamAV status:', e.message));
            console.log(`[LogFetcher] ClamAV is NOT installed on server ${serverId}`);
          }
          
          // Process scan files
          const scanFileList = (results.command_6 || '').toString().trim().split('\n').filter(f => f.trim());
          console.log(`[LogFetcher] Found ${scanFileList.length} scan files on server ${serverId}`);
          
          // Create promises for each scan file read
          const scanPromises = scanFileList.map(filePath => {
            return new Promise((resolveFile) => {
              if (!filePath.trim()) {
                resolveFile();
                return;
              }
              
              ssh.exec(`sudo cat "${filePath.trim()}"`, (err, stream) => {
                let fileContent = '';
                let errorContent = '';
                let closed = false;
                
                if (err) {
                  console.log(`[LogFetcher] Error reading scan file: ${filePath} - ${err.message}`);
                  resolveFile();
                  return;
                }
                
                if (!stream) {
                  console.log(`[LogFetcher] No stream for scan file: ${filePath}`);
                  resolveFile();
                  return;
                }
                
                stream.on('data', (data) => { 
                  fileContent += data.toString(); 
                });
                
                stream.stderr.on('data', (data) => {
                  errorContent += data.toString();
                });
                
                // Use both 'close' and 'end' to ensure we get all data
                const finishProcessing = async () => {
                  if (closed) return; // Only process once
                  closed = true;
                  
                  console.log(`[LogFetcher] Stream finished for ${filePath} - content size: ${fileContent.length} bytes`);
                  
                  if (errorContent.length > 0) {
                    console.log(`[LogFetcher] SSH stderr: ${errorContent.substring(0, 200)}`);
                  }
                  
                  if (fileContent.length < 20) {
                    console.log(`[LogFetcher] Scan file too small (${fileContent.length} bytes): ${filePath}`);
                    console.log(`[LogFetcher] Content: ${fileContent}`);
                    resolveFile();
                    return;
                  }
                  
                  try {
                    console.log(`[LogFetcher] Processing: ${filePath} (${fileContent.length} bytes)`);
                    
                    // Find all SCAN SUMMARY positions
                    const scanPositions = [];
                    let searchIndex = 0;
                    while (true) {
                      const pos = fileContent.indexOf('----------- SCAN SUMMARY -----------', searchIndex);
                      if (pos === -1) break;
                      scanPositions.push(pos);
                      searchIndex = pos + 1;
                    }
                    
                    if (scanPositions.length === 0) {
                      console.log(`[LogFetcher] No SCAN SUMMARY in ${filePath}`);
                      resolveFile();
                      return;
                    }
                    
                    console.log(`[LogFetcher] Found ${scanPositions.length} scan summary(ies)`);
                    
                    // Process each scan
                    for (let scanIndex = 0; scanIndex < scanPositions.length; scanIndex++) {
                      // Find separator line before this summary (marks end of file listing for this scan)
                      const summaryPos = scanPositions[scanIndex];
                      
                      // Search backwards for the separator line (------)
                      let separatorPos = summaryPos;
                      for (let i = summaryPos - 1; i >= 0; i--) {
                        if (fileContent[i] === '\n') {
                          const lineStart = i + 1;
                          const nextNewline = fileContent.indexOf('\n', lineStart);
                          const line = fileContent.substring(lineStart, nextNewline > -1 ? nextNewline : fileContent.length);
                          if (line.startsWith('-------')) {
                            separatorPos = lineStart;
                            break;
                          }
                        }
                      }
                      
                      // Scan section starts from either start of file or end of previous summary
                      let scanStart = 0;
                      if (scanIndex > 0) {
                        const prevSummaryPos = scanPositions[scanIndex - 1];
                        // Find where the previous summary ends (look for the End Date line)
                        const endDatePos = fileContent.indexOf('End Date:', prevSummaryPos);
                        if (endDatePos > -1) {
                          // Find the newline after End Date line
                          const endOfLine = fileContent.indexOf('\n', endDatePos);
                          if (endOfLine > -1) {
                            scanStart = endOfLine + 1;
                          }
                        }
                      }
                      
                      // Find next summary position (or end of file)
                      const nextSummaryPos = scanIndex < scanPositions.length - 1 ? scanPositions[scanIndex + 1] : fileContent.length;
                      
                      // Extract the complete scan content (from file start or after previous summary to next summary or EOF)
                      const scanContent = fileContent.substring(scanStart, nextSummaryPos);
                      
                      // Parse summary from the content
                      const summaryMatch = scanContent.match(/----------- SCAN SUMMARY -----------\s*([\s\S]*?)(?:End Date[^\n]*\n)/);
                      if (!summaryMatch) {
                        console.log(`[LogFetcher] Could not parse summary for scan #${scanIndex + 1}`);
                        continue;
                      }
                      
                      const fullSummary = summaryMatch[0];
                      const startDateMatch = fullSummary.match(/Start Date:\s*(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                      const endDateMatch = fullSummary.match(/End Date:\s*(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                      const scannedFilesMatch = fullSummary.match(/Scanned files:\s*(\d+)/);
                      const infectedFilesMatch = fullSummary.match(/Infected files:\s*(\d+)/);
                      
                      if (!startDateMatch || !endDateMatch) {
                        console.log(`[LogFetcher] Could not parse dates for scan #${scanIndex + 1}`);
                        continue;
                      }
                      
                      const startTime = new Date(`${startDateMatch[1]}-${startDateMatch[2]}-${startDateMatch[3]}T${startDateMatch[4]}:${startDateMatch[5]}:${startDateMatch[6]}`);
                      const endTime = new Date(`${endDateMatch[1]}-${endDateMatch[2]}-${endDateMatch[3]}T${endDateMatch[4]}:${endDateMatch[5]}:${endDateMatch[6]}`);
                      const filesScanned = parseInt(scannedFilesMatch?.[1] || 0);
                      const threatsFound = parseInt(infectedFilesMatch?.[1] || 0);
                      
                      console.log(`[LogFetcher] Processing scan #${scanIndex + 1}: Start=${startTime.toISOString()}, Files=${filesScanned}, Threats=${threatsFound}`);
                      
                      // Check if scan already exists
                      const existingRes = await pool.query(
                        'SELECT id FROM scan_results WHERE server_id = $1 AND start_time = $2',
                        [serverId, startTime]
                      ).catch(() => ({ rows: [] }));
                      
                      let isNewScan = existingRes.rows.length === 0;
                      let scanId = null;
                      
                      if (isNewScan) {
                        // Insert new scan
                        const insertRes = await pool.query(
                          `INSERT INTO scan_results (server_id, start_time, end_time, status, files_scanned, threats_found, raw_output)
                           VALUES ($1, $2, $3, $4, $5, $6, $7) 
                           RETURNING id`,
                          [serverId, startTime, endTime, 'completed', filesScanned, threatsFound, scanContent]
                        ).catch(e => {
                          console.error('[LogFetcher] Insert scan error:', e.message);
                          return { rows: [] };
                        });
                        
                        if (insertRes.rows.length > 0) {
                          scanId = insertRes.rows[0].id;
                          console.log(`[LogFetcher] ✅ Saved NEW scan #${scanIndex + 1}: ${filesScanned} files, ${threatsFound} threats`);
                        } else {
                          console.log(`[LogFetcher] ⚠️  Could not insert scan #${scanIndex + 1}`);
                        }
                      } else {
                        scanId = existingRes.rows[0].id;
                        console.log(`[LogFetcher] ⏭️  Scan #${scanIndex + 1} already exists - skipping threats/alerts`);
                      }
                      
                      // Parse threats ONLY for NEW scans
                      if (isNewScan && scanId) {
                        // Extract FOUND lines - only from the BEGINNING part (file listing) before SCAN SUMMARY
                        const summaryStartPos = scanContent.indexOf('----------- SCAN SUMMARY -----------');
                        const fileListingPart = scanContent.substring(0, summaryStartPos);
                        const lines = fileListingPart.split('\n');
                        const foundLines = lines.filter(line => line.includes('FOUND'));
                        
                        console.log(`[LogFetcher] Parsing threats for NEW scan #${scanIndex + 1}: ${foundLines.length} FOUND lines detected`);
                        
                        let detectionsSaved = 0;
                        const alertsToCreate = [];
                        
                        for (const line of foundLines) {
                          try {
                            // Match: /path/to/file: THREAT_NAME FOUND
                            const match = line.match(/^(.+?):\s+(.+?)\s+FOUND\s*$/);
                            if (match) {
                              const filePath = match[1].trim();
                              const threatName = match[2].trim();
                              
                              // Skip empty values
                              if (!filePath || !threatName) {
                                console.log(`[LogFetcher] Skipping empty values: path="${filePath}" threat="${threatName}"`);
                                continue;
                              }
                              
                              const detRes = await pool.query(
                                `INSERT INTO detections (scan_result_id, server_id, file_path, threat_name, severity)
                                 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
                                [scanId, serverId, filePath, threatName, 'high']
                              );
                              
                              if (detRes.rows.length > 0) {
                                detectionsSaved++;
                                alertsToCreate.push(detRes.rows[0].id);
                                console.log(`[LogFetcher] ✅ Recorded detection #${detectionsSaved}: ${filePath} - ${threatName}`);
                              }
                            } else {
                              console.log(`[LogFetcher] ⚠️  Could not parse line: ${line.substring(0, 80)}`);
                            }
                          } catch (e) {
                            console.error(`[LogFetcher] Error processing threat line: ${e.message}`);
                          }
                        }
                        
                        console.log(`[LogFetcher] ✅ Saved ${detectionsSaved} detections from ${foundLines.length} threat lines`);
                        
                        // Create alerts for newly detected threats
                        if (alertsToCreate.length > 0) {
                          try {
                            console.log(`[LogFetcher] Creating alerts for ${alertsToCreate.length} new detections...`);
                            let alertsCreated = 0;
                            
                            for (const detectionId of alertsToCreate) {
                              try {
                                const createRes = await pool.query(
                                  `INSERT INTO alerts (server_id, detection_id, alert_type, message, is_sent)
                                   VALUES ($1, $2, $3, $4, $5) RETURNING id`,
                                  [serverId, detectionId, 'threat_detected', `Threat detected on server ${server.name}`, false]
                                );
                                if (createRes.rows.length > 0) {
                                  alertsCreated++;
                                  console.log(`[LogFetcher] ✅ Created alert for detection ${detectionId}`);
                                }
                              } catch (e) {
                                console.error('[LogFetcher] Error creating alert for detection', detectionId, ':', e.message);
                              }
                            }
                            
                            console.log(`[LogFetcher] ✅ Successfully created ${alertsCreated} alerts`);
                            
                            // Send alert emails immediately after detection
                            if (alertsCreated > 0) {
                              console.log('[LogFetcher] Sending alert emails for new threats...');
                              await sendPendingAlerts();
                            }
                          } catch (e) {
                            console.error('[LogFetcher] Error creating alerts:', e.message);
                          }
                        } else {
                          console.log(`[LogFetcher] No threats found in scan #${scanIndex + 1}`);
                        }
                      }
                    }
                  } catch (e) {
                    console.error('[LogFetcher] Parse error:', e.message);
                  }
                  
                  resolveFile();
                };
                
                stream.on('end', finishProcessing);
                stream.on('close', finishProcessing);
              });
            });
          });
          
          // Wait for all scan files to be processed
          console.log(`[LogFetcher] Waiting for ${scanPromises.length} scan files to be processed...`);
          await Promise.all(scanPromises);
          console.log(`[LogFetcher] All scan files processed`);
          
          // Check if any previous unresolved detections have been fixed
          try {
            // Get the latest scan for this server (just completed)
            const latestScan = await pool.query(
              `SELECT sr.id, sr.start_time FROM scan_results sr 
               WHERE sr.server_id = $1 
               ORDER BY sr.start_time DESC LIMIT 1`,
              [serverId]
            );
            
            if (latestScan.rows.length > 0) {
              const latestScanStartTime = new Date(latestScan.rows[0].start_time);
              
              // Get all unresolved detections for this server that are older than the latest scan
              const unresolvedDetections = await pool.query(
                `SELECT id, file_path, threat_name FROM detections 
                 WHERE server_id = $1 
                 AND resolved_at IS NULL 
                 AND created_at < $2
                 ORDER BY id DESC`,
                [serverId, latestScanStartTime]
              );
              
              if (unresolvedDetections.rows.length > 0) {
                console.log(`[LogFetcher] Checking ${unresolvedDetections.rows.length} unresolved detections older than latest scan...`);
                
                for (const detection of unresolvedDetections.rows) {
                  // Check if this file_path + threat_name combo exists in the latest scan or any scan AFTER it
                  const stillFoundAfter = await pool.query(
                    `SELECT COUNT(*) as count FROM detections d
                     JOIN scan_results sr ON d.scan_result_id = sr.id
                     WHERE d.server_id = $1 
                     AND d.file_path = $2 
                     AND d.threat_name = $3
                     AND sr.start_time >= $4`,
                    [serverId, detection.file_path, detection.threat_name, latestScanStartTime]
                  );
                  
                  const count = parseInt(stillFoundAfter.rows[0].count);
                  
                  // If it wasn't found in any recent scan, mark as resolved
                  if (count === 0) {
                    await pool.query(
                      `UPDATE detections 
                       SET resolved_at = NOW() 
                       WHERE id = $1`,
                      [detection.id]
                    );
                    console.log(`[LogFetcher] ✅ Marked as resolved: ${detection.threat_name} in ${detection.file_path}`);
                  }
                }
              }
            }
          } catch (e) {
            console.error('[LogFetcher] Error checking resolved detections:', e.message);
          }
          
          // Now process cronjobs and other data
          const cronOutput = (results.command_4 || '').toString();
          const detectedJobs = [];
          
          if (cronOutput && !cronOutput.includes('No system cronjobs')) {
            const lines = cronOutput.split('\n').filter(line => line.trim());
            let currentJobId = null;
            
            for (const line of lines) {
              const jobIdMatch = line.match(/# ClamOrchestra-Job-ID: (\d+)/);
              if (jobIdMatch) {
                currentJobId = parseInt(jobIdMatch[1]);
                continue;
              }
              
              if (line.startsWith('#')) continue;
              
              const cronMatch = line.match(/^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(.+)$/);
              if (cronMatch) {
                const cron_expression = `${cronMatch[1]} ${cronMatch[2]} ${cronMatch[3]} ${cronMatch[4]} ${cronMatch[5]}`;
                const command = cronMatch[6];
                
                detectedJobs.push({
                  server_id: serverId,
                  scan_job_id: currentJobId,
                  cron_expression,
                  command
                });
                
                currentJobId = null;
              }
            }
          }
          
          // Save detected cronjobs to database
          if (detectedJobs.length > 0) {
            console.log(`[LogFetcher] Found ${detectedJobs.length} cronjobs on server ${serverId}`);
            
            for (const job of detectedJobs) {
              if (job.scan_job_id) {
                await pool.query(
                  `DELETE FROM detected_cronjobs WHERE server_id = $1 AND scan_job_id = $2`,
                  [job.server_id, job.scan_job_id]
                ).catch(e => console.error('[LogFetcher] Error deleting old cronjob:', e.message));
                
                await pool.query(
                  `INSERT INTO detected_cronjobs (server_id, scan_job_id, cron_expression, command) 
                   VALUES ($1, $2, $3, $4)`,
                  [job.server_id, job.scan_job_id, job.cron_expression, job.command]
                ).catch(e => console.error('[LogFetcher] Error inserting updated cronjob:', e.message));
              } else {
                await pool.query(
                  `INSERT INTO detected_cronjobs (server_id, scan_job_id, cron_expression, command) 
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (server_id, cron_expression, command) 
                   DO UPDATE SET updated_at = NOW()`,
                  [job.server_id, null, job.cron_expression, job.command]
                ).catch(e => console.error('[LogFetcher] Error saving cronjob:', e.message));
              }
            }
          } else {
            console.log(`[LogFetcher] No cronjobs found on server ${serverId}`);
          }
          
          // Clean up cronjobs
          if (detectedJobs.length === 0) {
            await pool.query(`DELETE FROM detected_cronjobs WHERE server_id = $1`, [serverId])
              .catch(e => console.error('[LogFetcher] Error cleaning up cronjobs:', e.message));
          } else {
            await pool.query(`DELETE FROM detected_cronjobs WHERE server_id = $1 AND scan_job_id IS NULL`, [serverId])
              .catch(e => console.error('[LogFetcher] Error cleaning up old cronjobs:', e.message));
          }
          
          // Store signature update date
          const signatureDateOutput = (results.command_5 || '').toString().trim();
          if (signatureDateOutput && signatureDateOutput !== 'Unknown') {
            try {
              const dateStr = signatureDateOutput.split(' +')[0];
              await pool.query(
                'UPDATE servers SET signature_updated_at = $1 WHERE id = $2',
                [dateStr, serverId]
              ).catch(e => console.error('[LogFetcher] Error updating signature date:', e.message));
              console.log(`[LogFetcher] Updated signature date for server ${serverId}: ${dateStr}`);
            } catch (e) {
              console.error('[LogFetcher] Error parsing signature date:', e.message);
            }
          }
          
          // Update last_log_fetch timestamp
          await pool.query(
            'UPDATE log_fetch_schedules SET last_fetch = NOW() WHERE server_id = $1',
            [serverId]
          ).catch(e => console.error('Error updating fetch time:', e.message));
          
          ssh.end();
          resolve();
        });
      });
      
      ssh.on('error', (err) => {
        console.error(`[LogFetcher] SSH error: ${err.message}`);
        resolve();
      });
      
      ssh.connect({
        host: server.ip_address || server.hostname,
        port: server.port || 22,
        username: server.ssh_user || 'root',
        privateKey: privateKey,
        readyTimeout: 15000,
        tryKeyboard: false
      });
      
      setTimeout(() => {
        ssh.end();
        resolve();
      }, 60000);
    });
  } catch (error) {
    console.error('[LogFetcher] Error fetching logs:', error.message);
  }
}

// Helper to execute multiple commands sequentially
function executeCommands(ssh, commands, callback) {
  const results = {};
  let index = 0;
  
  function executeNext() {
    if (index >= commands.length) {
      callback(results);
      return;
    }
    
    const cmd = commands[index];
    const key = `command_${index}`;
    
    ssh.exec(cmd, (err, stream) => {
      if (err) {
        results[key] = `Error: ${err.message}`;
        index++;
        executeNext();
        return;
      }
      
      let output = '';
      stream.on('data', (data) => {
        output += data.toString();
      });
      
      stream.on('close', () => {
        results[key] = output;
        index++;
        executeNext();
      });
    });
  }
  
  executeNext();
}

// ============= MIDDLEWARE =============
app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

// ============= PASSPORT AUTH =============
passport.use(new LocalStrategy.Strategy(async (username, password, done) => {
  try {
    const result = await pool.query('SELECT id, username, password_hash, is_admin FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return done(null, false, { message: 'User not found' });
    
    const user = result.rows[0];
    const isValid = await bcryptjs.compare(password, user.password_hash);
    if (!isValid) return done(null, false, { message: 'Invalid password' });
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT id, username, is_admin FROM users WHERE id = $1', [id]);
    done(null, result.rows[0] || false);
  } catch (error) {
    done(error);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// ============= AUTH MIDDLEWARE =============
const requireAuth = (req, res, next) => {
  // Check if authenticated via session or cookie
  if (req.isAuthenticated?.()) return next();
  
  // Check for authToken cookie
  if (req.cookies?.authToken) {
    try {
      const decoded = jwt.verify(req.cookies.authToken, process.env.JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (e) {
      res.clearCookie('authToken');
    }
  }
  
  // Check for HTML request (redirect) or JSON (401)
  if (req.accepts('html')) return res.redirect('/login');
  return res.status(401).json({ error: 'Unauthorized' });
};

// ============= ROUTES =============

// Login page
app.get('/login', (req, res) => {
  if (req.isAuthenticated?.()) return res.redirect('/');
  res.render('login', { error: null });
});

// Login POST
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).render('login', { error: 'Error' });
    if (!user) return res.status(401).render('login', { error: info.message });
    
    req.logIn(user, (err) => {
      if (err) return res.status(500).render('login', { error: 'Login failed' });
      
      const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin },
        process.env.JWT_SECRET, { expiresIn: '24h' });
      
      res.cookie('authToken', token, { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 });
      
      // Always redirect to dashboard, never return JSON for form submissions
      res.redirect('/');
    });
  })(req, res, next);
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('authToken');
  req.logOut((err) => {
    res.redirect('/login');
  });
});

// Dashboard
app.get('/', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Servers list
app.get('/servers', requireAuth, (req, res) => {
  res.render('servers', { user: req.user });
});

// API: Get servers
app.get('/api/servers', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM servers ORDER BY created_at DESC');
    
    // Ensure all servers have clamav_configs entries
    for (const server of result.rows) {
      await pool.query(
        'INSERT INTO clamav_configs (server_id, is_installed) VALUES ($1, $2) ON CONFLICT (server_id) DO NOTHING',
        [server.id, false]
      ).catch(e => {
        // Ignore constraint errors - entry might already exist
        if (!e.message.includes('violates')) {
          console.warn(`[API] Warning: Could not ensure clamav_configs for server ${server.id}:`, e.message);
        }
      });
    }
    
    res.json({ servers: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Add server
app.post('/api/servers', requireAuth, async (req, res) => {
  try {
    const { name, hostname, ip_address, port, ssh_user, description } = req.body;
    const result = await pool.query(
      'INSERT INTO servers (name, hostname, ip_address, port, ssh_user, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name, hostname, ip_address, port || 22, ssh_user || 'root', description]
    );
    
    const serverId = result.rows[0].id;
    
    // Create initial ClamAV config entry
    await pool.query(
      'INSERT INTO clamav_configs (server_id, is_installed) VALUES ($1, $2)',
      [serverId, false]
    ).catch(e => console.error('Error creating clamav_config:', e.message));
    
    // Automatisch LogFetcher-Einstellungen erstellen
    await pool.query(
      'INSERT INTO log_fetch_schedules (server_id, frequency, daily_hour, weekly_day, weekly_hour, enabled) VALUES ($1, $2, $3, $4, $5, $6)',
      [serverId, 'hourly', 0, 0, 0, true]
    ).catch(e => console.error('Error creating log_fetch_schedule:', e.message));
    
    res.json({ server: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Delete server
app.delete('/api/servers/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM servers WHERE id = $1', [req.params.id]);
    res.json({ message: 'Server deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= LOG FETCHER MANAGEMENT =============

// Get LogFetcher settings for a server
app.get('/api/log-fetch-schedule/:serverId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM log_fetch_schedules WHERE server_id = $1',
      [req.params.serverId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Log fetch schedule not found' });
    }
    res.json({ schedule: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update LogFetcher settings for a server
app.put('/api/log-fetch-schedule/:serverId', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { frequency, daily_hour, weekly_day, weekly_hour, enabled } = req.body;
    
    const result = await pool.query(
      `UPDATE log_fetch_schedules 
       SET frequency = $1, daily_hour = $2, weekly_day = $3, weekly_hour = $4, enabled = $5
       WHERE server_id = $6
       RETURNING *`,
      [frequency || 'hourly', daily_hour || 0, weekly_day || 0, weekly_hour || 0, enabled !== false, req.params.serverId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Log fetch schedule not found' });
    }
    
    // Scheduler neu laden
    console.log(`[LogFetcher] Settings updated for server ${req.params.serverId}`);
    
    res.json({ schedule: result.rows[0], message: 'Log fetch schedule updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fetch logs immediately for a server
app.post('/api/log-fetch/:serverId/fetch-now', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    console.log(`[LogFetcher] Manual fetch triggered for server ${req.params.serverId}`);
    
    // Execute in background and send alerts after
    fetchServerLogs(req.params.serverId)
      .then(async () => {
        console.log(`[LogFetcher] Manual fetch completed, sending pending alerts...`);
        await sendPendingAlerts();
      })
      .catch(e => console.error('Fetch error:', e.message));
    
    res.json({ message: 'Log fetch started, please check back in a moment', status: 'fetching' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get detected cronjobs for a server
app.get('/api/detected-cronjobs/:serverId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM detected_cronjobs WHERE server_id = $1 ORDER BY updated_at DESC',
      [req.params.serverId]
    );
    res.json({ cronjobs: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete detected cronjob from database and server
app.delete('/api/detected-cronjobs/:jobId', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    // Get the cronjob details
    const jobRes = await pool.query('SELECT * FROM detected_cronjobs WHERE id = $1', [req.params.jobId]);
    if (jobRes.rows.length === 0) {
      return res.status(404).json({ error: 'Cronjob not found' });
    }
    
    const job = jobRes.rows[0];
    const serverId = job.server_id;
    
    // Get server details for SSH
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
    if (serverRes.rows.length === 0) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    const server = serverRes.rows[0];
    
    // Get SSH key
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    if (keyRes.rows.length === 0) {
      return res.status(400).json({ error: 'No default SSH key configured' });
    }
    
    const key = keyRes.rows[0];
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    return new Promise((resolve) => {
      const ssh = new SSHClient();
      
      ssh.on('ready', () => {
        // Remove cronjob from server by editing /etc/cron.d/clamorchestra-scans
        const removeCommand = `sudo sed -i '/${job.cron_expression.replace(/\//g, '\\/')}/d' /etc/cron.d/clamorchestra-scans && sudo systemctl restart cron 2>/dev/null || true`;
        
        ssh.exec(removeCommand, (err, stream) => {
          if (err) {
            console.error(`[CronjobDelete] Error removing cronjob: ${err.message}`);
            ssh.end();
            return resolve(res.status(500).json({ error: err.message }));
          }
          
          stream.on('close', async (code) => {
            ssh.end();
            
            // Remove from database
            await pool.query('DELETE FROM detected_cronjobs WHERE id = $1', [req.params.jobId])
              .catch(e => console.error('Error deleting cronjob from DB:', e.message));
            
            console.log(`[CronjobDelete] Cronjob removed from server ${serverId}`);
            resolve(res.json({ message: 'Cronjob deleted successfully', status: 'deleted' }));
          });
          
          stream.on('data', (data) => {
            console.log(`[CronjobDelete] Output: ${data.toString()}`);
          });
        });
      });
      
      ssh.on('error', (err) => {
        console.error(`[CronjobDelete] SSH error: ${err.message}`);
        resolve(res.status(500).json({ error: `SSH Error: ${err.message}` }));
      });
      
      ssh.connect({
        host: server.ip_address || server.hostname,
        port: server.port || 22,
        username: server.ssh_user || 'root',
        privateKey: privateKey,
        readyTimeout: 15000,
        tryKeyboard: false
      });
      
      setTimeout(() => {
        ssh.end();
        if (!res.headersSent) {
          resolve(res.status(500).json({ error: 'Delete timeout' }));
        }
      }, 30000);
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Get scan results
app.get('/api/scans', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT sr.*, s.name as server_name 
      FROM scan_results sr
      JOIN servers s ON sr.server_id = s.id
      ORDER BY sr.created_at DESC LIMIT 20
    `);
    res.json({ scans: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Get single scan details
app.get('/api/scans/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT sr.*, s.name as server_name 
      FROM scan_results sr
      JOIN servers s ON sr.server_id = s.id
      WHERE sr.id = $1
    `, [req.params.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Scan nicht gefunden' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Get detections
app.get('/api/detections', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.*, s.name as server_name, sr.start_time as scan_time
      FROM detections d
      JOIN servers s ON d.server_id = s.id
      LEFT JOIN scan_results sr ON d.scan_result_id = sr.id
      ORDER BY d.created_at DESC LIMIT 50
    `);
    res.json({ detections: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= SSH KEYS MANAGEMENT =============

// SSH Keys list
app.get('/api/ssh-keys', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('SELECT id, key_name, ssh_user, is_default FROM ssh_keys ORDER BY created_at DESC');
    res.json({ keys: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Upload SSH Key
app.post('/api/ssh-keys/upload', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { key_name, public_key, private_key, ssh_user, is_default } = req.body;
    
    // Validate that private_key is actually a private key, not a public key
    const privateKeyTrimmed = (private_key || '').trim();
    
    if (!privateKeyTrimmed) {
      return res.status(400).json({ error: 'Private key cannot be empty' });
    }
    
    if (privateKeyTrimmed.startsWith('ssh-rsa') || privateKeyTrimmed.startsWith('ssh-ed25519') || privateKeyTrimmed.startsWith('ecdsa-sha2')) {
      return res.status(400).json({ 
        error: 'Error: This appears to be a PUBLIC key, not a PRIVATE key. Please upload the PRIVATE key file (usually starts with -----BEGIN PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----)' 
      });
    }
    
    if (!privateKeyTrimmed.includes('PRIVATE KEY')) {
      return res.status(400).json({ 
        error: 'Invalid private key format. Must contain "PRIVATE KEY" header.' 
      });
    }
    
    if (is_default) {
      await pool.query('UPDATE ssh_keys SET is_default = FALSE');
    }
    
    const result = await pool.query(
      'INSERT INTO ssh_keys (key_name, public_key, private_key, ssh_user, is_default) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [key_name, public_key, privateKeyTrimmed, ssh_user || 'clam', is_default || false]
    );
    res.json({ id: result.rows[0].id, message: 'SSH key added successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete SSH Key
app.delete('/api/ssh-keys/:id', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM ssh_keys WHERE id = $1', [req.params.id]);
    res.json({ message: 'SSH key deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test SSH Connection
app.post('/api/servers/:serverId/test-connection', requireAuth, async (req, res) => {
  try {
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [req.params.serverId]);
    if (serverRes.rows.length === 0) {
      return res.status(404).json({ error: 'Server not found', status: 'error' });
    }
    
    const server = serverRes.rows[0];
    
    // Get default SSH key
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    
    if (keyRes.rows.length === 0) {
      return res.status(400).json({ error: 'No default SSH key configured', status: 'error' });
    }
    
    const key = keyRes.rows[0];
    
    // Normalize private key format (convert escaped newlines to actual newlines)
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    console.log(`[SSH Test] Connecting to ${server.ip_address || server.hostname}:${server.port || 22} as ${server.ssh_user || 'root'}`);
    console.log(`[SSH Test] Key starts with: ${privateKey.substring(0, 30)}`);
    console.log(`[SSH Test] Key length: ${privateKey.length} characters`);
    
    return new Promise((resolve) => {
      const ssh = new SSHClient();
      
      ssh.on('ready', () => {
        console.log('[SSH Test] ✅ Authentication successful');
        ssh.end();
        
        // Update server status to online
        pool.query(
          'UPDATE servers SET status = $1, last_check = NOW() WHERE id = $2',
          ['online', req.params.serverId]
        ).catch(err => console.error('Error updating server status:', err));
        
        resolve(res.json({ 
          status: 'success',
          message: 'SSH connection successful',
          online: true
        }));
      });
      
      ssh.on('error', (err) => {
        console.log(`[SSH Test] ❌ Connection error: ${err.message}`);
        console.log(`[SSH Test] Error code: ${err.code}`);
        
        // Update server status to offline
        pool.query(
          'UPDATE servers SET status = $1, last_check = NOW() WHERE id = $2',
          ['offline', req.params.serverId]
        ).catch(e => console.error('Error updating server status:', e));
        
        resolve(res.json({
          status: 'error',
          message: err.message || 'Connection failed',
          online: false
        }));
      });
      
      const connectConfig = {
        host: server.ip_address || server.hostname,
        port: server.port || 22,
        username: server.ssh_user || 'root',
        privateKey: privateKey,
        readyTimeout: 15000,
        tryKeyboard: false,
        algorithms: {
          serverHostKey: ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'],
          cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'],
          serverHostKeyAlgo: ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519']
        }
      };
      
      console.log(`[SSH Test] Connect config:`, {
        host: connectConfig.host,
        port: connectConfig.port,
        username: connectConfig.username,
        keyFormat: privateKey.includes('OPENSSH') ? 'OpenSSH' : 'PEM'
      });
      
      ssh.connect(connectConfig);
      
      // Timeout nach 10 Sekunden
      setTimeout(() => {
        ssh.end();
        if (!res.headersSent) {
          resolve(res.json({
            status: 'error',
            message: 'Connection timeout',
            online: false
          }));
        }
      }, 10000);
    });
  } catch (error) {
    res.status(500).json({ error: error.message, status: 'error' });
  }
});

// ============= CLAMAV MANAGEMENT =============

// Get ClamAV config
app.get('/api/clamav/config/:serverId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clamav_configs WHERE server_id = $1', [req.params.serverId]);
    if (result.rows.length === 0) {
      return res.json({ config: { is_installed: false } });
    }
    res.json({ config: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Install ClamAV
app.post('/api/clamav/install/:serverId', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [req.params.serverId]);
    if (serverRes.rows.length === 0) return res.status(404).json({ error: 'Server not found' });
    
    const server = serverRes.rows[0];
    
    // Get default SSH key
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    if (keyRes.rows.length === 0) return res.status(400).json({ error: 'No default SSH key configured' });
    
    const key = keyRes.rows[0];
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    const installScript = `sudo apt-get update && sudo apt-get install -y clamav clamav-daemon clamav-freshclam`;
    
    return new Promise((resolve) => {
      const ssh = new SSHClient();
      let output = '';
      let errorOutput = '';
      
      ssh.on('ready', () => {
        ssh.exec(installScript, (err, stream) => {
          if (err) {
            ssh.end();
            return resolve(res.status(500).json({ error: err.message }));
          }
          
          stream.on('close', (code, signal) => {
            ssh.end();
            
            console.log(`[ClamAV Install] Exit code: ${code}`);
            console.log(`[ClamAV Install] Output: ${output}`);
            
            if (code === 0) {
              // Mark as installed in database
              pool.query(
                'INSERT INTO clamav_configs (server_id, is_installed, version) VALUES ($1, $2, $3) ON CONFLICT (server_id) DO UPDATE SET is_installed = $2, updated_at = NOW()',
                [req.params.serverId, true, 'latest']
              ).catch(e => console.error('Error updating ClamAV config:', e));
              
              resolve(res.json({ 
                message: 'ClamAV installation successful',
                success: true,
                output: output 
              }));
            } else {
              resolve(res.status(500).json({ 
                error: 'Installation failed',
                output: errorOutput || output,
                code: code
              }));
            }
          });
          
          stream.on('data', (data) => {
            output += data.toString();
          });
          
          stream.stderr.on('data', (data) => {
            errorOutput += data.toString();
          });
        });
      });
      
      ssh.on('error', (err) => {
        resolve(res.status(500).json({ error: `SSH Error: ${err.message}` }));
      });
      
      ssh.connect({
        host: server.ip_address || server.hostname,
        port: server.port || 22,
        username: server.ssh_user || 'root',
        privateKey: privateKey,
        readyTimeout: 15000,
        tryKeyboard: false
      });
      
      setTimeout(() => {
        ssh.end();
        if (!res.headersSent) {
          resolve(res.status(500).json({ error: 'Installation timeout' }));
        }
      }, 60000);
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update ClamAV signatures
app.post('/api/clamav/update-signatures/:serverId', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [req.params.serverId]);
    if (serverRes.rows.length === 0) return res.status(404).json({ error: 'Server not found' });
    
    const server = serverRes.rows[0];
    
    // Get default SSH key
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    if (keyRes.rows.length === 0) return res.status(400).json({ error: 'No default SSH key configured' });
    
    const key = keyRes.rows[0];
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    // Run freshclam in background (non-blocking) - kill any existing processes first
    const updateScript = `sudo killall freshclam 2>/dev/null; sleep 1; nohup sudo /usr/bin/freshclam > /var/log/clamav/freshclam-update.log 2>&1 &`;
    
    const ssh = new SSHClient();
    
    ssh.on('ready', () => {
      ssh.exec(updateScript, (err, stream) => {
        if (err) {
          console.error(`[Freshclam] SSH exec error: ${err.message}`);
          ssh.end();
          return;
        }
        
        // Close immediately - we don't wait for freshclam to complete
        ssh.end();
        console.log(`[Freshclam] Background update initiated for server ${req.params.serverId}`);
      });
    });
    
    ssh.on('error', (err) => {
      console.error(`[Freshclam] SSH error: ${err.message}`);
    });
    
    ssh.connect({
      host: server.ip_address || server.hostname,
      port: server.port || 22,
      username: server.ssh_user || 'root',
      privateKey: privateKey,
      readyTimeout: 15000,
    });
    
    // Return immediately - update runs in background
    res.json({ 
      message: 'Signature update started in background on server',
      success: true
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update ClamAV config
app.put('/api/clamav/config/:serverId', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { freshclam_enabled, clamd_enabled } = req.body;
    await pool.query(
      'UPDATE clamav_configs SET freshclam_enabled = $1, clamd_enabled = $2 WHERE server_id = $3',
      [freshclam_enabled, clamd_enabled, req.params.serverId]
    );
    res.json({ message: 'Config updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= SCAN MANAGEMENT =============

// List scan jobs
app.get('/api/scans/jobs/:serverId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM scan_jobs WHERE server_id = $1 ORDER BY created_at DESC',
      [req.params.serverId]
    );
    res.json({ jobs: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all scan jobs with server names
app.get('/api/scans/jobs/all', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT sj.*, s.name as server_name FROM scan_jobs sj JOIN servers s ON sj.server_id = s.id ORDER BY sj.created_at DESC'
    );
    res.json({ jobs: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create scan job
app.post('/api/scans/jobs', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { server_id, name, scan_type, paths, cron_expression } = req.body;
    
    // Create scan job in DB
    const result = await pool.query(
      'INSERT INTO scan_jobs (server_id, name, scan_type, paths, cron_expression) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [server_id, name, scan_type || 'quick', paths || ['/home'], cron_expression]
    );
    
    const job = result.rows[0];
    
    // Deploy cronjob to remote server
    await deployRemoteCronjob(server_id, job);
    
    res.json({ job, message: 'Scan job created and deployed to server' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Deploy scan cronjob to remote server
async function deployRemoteCronjob(serverId, job) {
  try {
    const serverRes = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
    if (serverRes.rows.length === 0) {
      console.error(`[ScanJob] Server ${serverId} not found`);
      return;
    }
    
    const server = serverRes.rows[0];
    
    const keyRes = await pool.query('SELECT * FROM ssh_keys WHERE is_default = TRUE LIMIT 1');
    if (keyRes.rows.length === 0) {
      console.error('[ScanJob] No default SSH key configured');
      return;
    }
    
    const key = keyRes.rows[0];
    let privateKey = key.private_key;
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n').trim();
    }
    
    const scanPaths = Array.isArray(job.paths) ? job.paths.join(' ') : job.paths || '/home';
    let scanCommand;
    
    if (job.scan_type === 'quick') {
      scanCommand = `clamscan -r --log=/var/log/clamav/scan_${job.id}.log ${scanPaths}`;
    } else if (job.scan_type === 'full') {
      scanCommand = `clamscan -r -i --log=/var/log/clamav/scan_${job.id}.log ${scanPaths}`;
    } else {
      scanCommand = `clamscan -r --log=/var/log/clamav/scan_${job.id}.log ${scanPaths}`;
    }
    
    // Create cron entry with unique job ID marker and root user (required for /etc/cron.d/ format)
    const jobMarker = `# ClamOrchestra-Job-ID: ${job.id}`;
    const cronEntry = `${jobMarker}\n${job.cron_expression} root ${scanCommand} > /dev/null 2>&1`;
    
    return new Promise((resolve) => {
      const ssh = new SSHClient();
      let output = '';
      
      ssh.on('ready', () => {
        // Add cronjob entry
        const installCron = `echo '${cronEntry}' | sudo tee -a /etc/cron.d/clamorchestra-scans > /dev/null && sudo systemctl restart cron 2>/dev/null || true`;
        
        ssh.exec(installCron, (err, stream) => {
          if (err) {
            console.error(`[ScanJob] Error deploying cron: ${err.message}`);
            ssh.end();
            resolve();
            return;
          }
          
          stream.on('close', (code) => {
            ssh.end();
            console.log(`[ScanJob] Cronjob deployed to server ${serverId} with exit code ${code}`);
            resolve();
          });
          
          stream.on('data', (data) => {
            output += data.toString();
          });
        });
      });
      
      ssh.on('error', (err) => {
        console.error(`[ScanJob] SSH error: ${err.message}`);
        resolve();
      });
      
      ssh.connect({
        host: server.ip_address || server.hostname,
        port: server.port || 22,
        username: server.ssh_user || 'root',
        privateKey: privateKey,
        readyTimeout: 15000,
        tryKeyboard: false
      });
      
      setTimeout(() => {
        ssh.end();
        resolve();
      }, 30000);
    });
  } catch (error) {
    console.error('[ScanJob] Error deploying remote cronjob:', error.message);
  }
}

// Get scan results
app.get('/api/scans/results/:serverId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM scan_results WHERE server_id = $1 ORDER BY start_time DESC LIMIT 20',
      [req.params.serverId]
    );
    res.json({ results: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get scan details
app.get('/api/scans/results/:resultId/details', requireAuth, async (req, res) => {
  try {
    const scan = (await pool.query('SELECT * FROM scan_results WHERE id = $1', [req.params.resultId])).rows[0];
    const detections = (await pool.query('SELECT * FROM detections WHERE scan_result_id = $1', [req.params.resultId])).rows;
    res.json({ scan, detections });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= DASHBOARD =============

// Dashboard summary
app.get('/api/dashboard/summary', requireAuth, async (req, res) => {
  try {
    const servers = await pool.query('SELECT COUNT(*) as count FROM servers');
    const scans = await pool.query('SELECT COUNT(*) as count FROM scan_results');
    const detections = await pool.query('SELECT COUNT(*) as count FROM detections');
    const activeDetections = await pool.query('SELECT COUNT(*) as count FROM detections WHERE resolved_at IS NULL');
    const resolvedDetections = await pool.query('SELECT COUNT(*) as count FROM detections WHERE resolved_at IS NOT NULL');
    const online = await pool.query('SELECT COUNT(*) as count FROM servers WHERE status = $1', ['online']);
    
    res.json({
      total_servers: parseInt(servers.rows[0].count),
      total_scans: parseInt(scans.rows[0].count),
      total_detections: parseInt(detections.rows[0].count),
      active_detections: parseInt(activeDetections.rows[0].count),
      resolved_detections: parseInt(resolvedDetections.rows[0].count),
      online_servers: parseInt(online.rows[0].count)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Recent scans
app.get('/api/dashboard/recent-scans', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT sr.*, s.name as server_name
      FROM scan_results sr
      JOIN servers s ON sr.server_id = s.id
      ORDER BY sr.created_at DESC LIMIT 10
    `);
    res.json({ scans: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Recent detections
app.get('/api/dashboard/recent-detections', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.*, s.name as server_name
      FROM detections d
      JOIN servers s ON d.server_id = s.id
      ORDER BY d.created_at DESC LIMIT 10
    `);
    res.json({ detections: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= ALERTS =============

// List alerts
app.get('/api/alerts', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT a.*, s.name as server_name
      FROM alerts a
      JOIN servers s ON a.server_id = s.id
      ORDER BY a.created_at DESC LIMIT 50
    `);
    res.json({ alerts: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark alert as sent
app.post('/api/alerts/:id/mark-sent', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query(
      'UPDATE alerts SET is_sent = TRUE, sent_at = CURRENT_TIMESTAMP WHERE id = $1',
      [req.params.id]
    );
    res.json({ message: 'Alert marked as sent' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= SETTINGS MANAGEMENT =============

// Get SMTP settings
app.get('/api/settings/smtp', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query(`
      SELECT setting_key, setting_value FROM system_settings 
      WHERE setting_key LIKE 'SMTP_%'
      ORDER BY setting_key
    `);
    
    const settings = {};
    result.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value || '';
    });
    
    res.json({ settings });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Save SMTP settings
app.put('/api/settings/smtp', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SECURE, SMTP_FROM } = req.body;
    
    const settings = [
      { key: 'SMTP_HOST', value: SMTP_HOST || '' },
      { key: 'SMTP_PORT', value: SMTP_PORT || '587' },
      { key: 'SMTP_USER', value: SMTP_USER || '' },
      { key: 'SMTP_PASSWORD', value: SMTP_PASSWORD || '' },
      { key: 'SMTP_SECURE', value: SMTP_SECURE === true ? 'true' : 'false' },
      { key: 'SMTP_FROM', value: SMTP_FROM || 'noreply@clamorchestra.local' }
    ];
    
    for (const setting of settings) {
      await pool.query(`
        INSERT INTO system_settings (setting_key, setting_value, updated_at) 
        VALUES ($1, $2, NOW())
        ON CONFLICT (setting_key) DO UPDATE SET setting_value = $2, updated_at = NOW()
      `, [setting.key, setting.value]);
    }
    
    // Re-initialize mailer with new settings
    await initializeMailer();
    console.log('[SMTP] Settings saved and mailer reinitialized');
    
    res.json({ message: 'SMTP settings saved', settings });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Change password
app.post('/api/user/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    
    // Validate input
    if (!current_password || !new_password || !confirm_password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    if (new_password !== confirm_password) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }
    
    if (new_password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Get current user from database
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userRes.rows[0];
    
    // Verify current password
    const passwordMatch = await bcryptjs.compare(current_password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newPasswordHash = await bcryptjs.hash(new_password, 10);
    
    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newPasswordHash, req.user.id]
    );
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('[ChangePassword] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Test email configuration
app.post('/api/settings/test-email', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { recipient_email } = req.body;
    console.log('[Email Test] ========== TEST EMAIL STARTED ==========');
    console.log('[Email Test] Recipient:', recipient_email);
    console.log('[Email Test] Requested by:', req.user?.username);
    
    if (!recipient_email) {
      console.log('[Email Test] ❌ ERROR: No recipient email provided');
      return res.status(400).json({ error: 'Recipient email is required' });
    }
    
    // Get current SMTP settings from database
    console.log('[Email Test] Fetching SMTP settings from database...');
    const settingsResult = await pool.query(`
      SELECT setting_key, setting_value FROM system_settings 
      WHERE setting_key LIKE 'SMTP_%'
    `);
    
    console.log('[Email Test] Found settings:', settingsResult.rows.length, 'rows');
    settingsResult.rows.forEach(row => {
      const masked = row.setting_value?.substring(0, 3) + '***' + (row.setting_value?.slice(-3) || '');
      console.log(`[Email Test]   - ${row.setting_key}: ${masked}`);
    });
    
    const settingsMap = {};
    settingsResult.rows.forEach(row => {
      const match = row.setting_key.match(/SMTP_(.+)/);
      if (match) {
        settingsMap[match[1]] = row.setting_value;
      }
    });
    
    // Log resolved SMTP config
    console.log('[Email Test] Resolved SMTP Configuration:');
    console.log('[Email Test]   HOST:', settingsMap['HOST'] || process.env.SMTP_HOST || 'localhost');
    console.log('[Email Test]   PORT:', settingsMap['PORT'] || process.env.SMTP_PORT || 587);
    console.log('[Email Test]   USER:', settingsMap['USER'] ? '✓ configured' : 'Not configured');
    console.log('[Email Test]   SECURE:', settingsMap['SECURE'] === 'true' ? 'Yes' : 'No');
    console.log('[Email Test]   FROM:', settingsMap['FROM'] || process.env.SMTP_FROM || 'noreply@clamorchestra.local');
    
    console.log('[Email Test] Getting mailer instance...');
    const currentMailer = getMailer();
    console.log('[Email Test] Mailer obtained:', currentMailer ? '✓ Ready' : '❌ Not available');
    
    // Verify mailer configuration
    if (currentMailer && currentMailer.transporter) {
      console.log('[Email Test] Mailer transporter config:', {
        host: currentMailer.transporter.options?.host,
        port: currentMailer.transporter.options?.port,
        secure: currentMailer.transporter.options?.secure,
        auth: currentMailer.transporter.options?.auth ? '✓ Configured' : 'None'
      });
    }
    
    // Test email
    const fromEmail = settingsMap['FROM'] || process.env.SMTP_FROM || 'noreply@clamorchestra.local';
    const mailOptions = {
      from: fromEmail,
      to: recipient_email,
      subject: '✅ ClamOrchestra - Test Email',
      html: `
        <h2>ClamOrchestra Email Configuration Test</h2>
        <p>This is a test email to verify your SMTP configuration is working correctly.</p>
        <p><strong>Test successful!</strong> Your email notifications are enabled.</p>
        <hr/>
        <p>
          <small>
            Sent at: ${new Date().toLocaleString('de-DE')}<br/>
            Server: ${process.env.HOST || 'localhost'}:${process.env.PORT || 3000}
          </small>
        </p>
      `
    };
    
    console.log('[Email Test] Email options prepared:');
    console.log('[Email Test]   From:', mailOptions.from);
    console.log('[Email Test]   To:', mailOptions.to);
    console.log('[Email Test]   Subject:', mailOptions.subject);
    console.log('[Email Test] Sending email...');
    
    const sendResult = await currentMailer.sendMail(mailOptions);
    console.log('[Email Test] ✅ Email sent successfully!');
    console.log('[Email Test]   Response ID:', sendResult.response?.substring(0, 50));
    console.log('[Email Test]   Message ID:', sendResult.messageId);
    
    res.json({ 
      success: true, 
      message: `Test email sent successfully to ${recipient_email}`,
      messageId: sendResult.messageId,
      config: {
        smtp_host: settingsMap['HOST'] || process.env.SMTP_HOST || 'localhost',
        smtp_port: settingsMap['PORT'] || process.env.SMTP_PORT || 587,
        smtp_user: (settingsMap['USER'] || process.env.SMTP_USER) ? '✓ configured' : 'Not configured',
        smtp_from: fromEmail
      }
    });
  } catch (error) {
    console.error('[Email Test] ========== TEST EMAIL FAILED ==========');
    console.error('[Email Test] Error Type:', error.constructor.name);
    console.error('[Email Test] Error Code:', error.code);
    console.error('[Email Test] Error Message:', error.message);
    console.error('[Email Test] Full Error:', error);
    
    if (error.message.includes('ECONNREFUSED')) {
      console.error('[Email Test] ❌ Connection refused - SMTP server not reachable');
    } else if (error.message.includes('ETIMEDOUT')) {
      console.error('[Email Test] ❌ Connection timeout - SMTP server not responding');
    } else if (error.message.includes('Authentication')) {
      console.error('[Email Test] ❌ Authentication failed - Invalid SMTP credentials');
    } else if (error.message.includes('Invalid')) {
      console.error('[Email Test] ❌ Invalid configuration - Check SMTP settings');
    }
    
    res.status(500).json({ 
      success: false,
      error: error.message,
      errorCode: error.code,
      errorType: error.constructor.name,
      hint: 'Check your SMTP settings in the Settings panel - See server logs for details'
    });
  }
  console.log('[Email Test] ==========================================\n');
});

// Get Alert Email settings
app.get('/api/settings/alert-email', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query(`
      SELECT setting_key, setting_value FROM system_settings 
      WHERE setting_key = 'ALERT_EMAIL_TO'
    `);
    
    const alertEmail = result.rows?.[0]?.setting_value || 'admin@clamorchestra.local';
    res.json({ 
      ALERT_EMAIL_TO: alertEmail 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Save Alert Email settings
app.put('/api/settings/alert-email', requireAuth, async (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  try {
    const { ALERT_EMAIL_TO } = req.body;
    
    if (!ALERT_EMAIL_TO || !ALERT_EMAIL_TO.includes('@')) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    
    await pool.query(`
      INSERT INTO system_settings (setting_key, setting_value, updated_at) 
      VALUES ($1, $2, NOW())
      ON CONFLICT (setting_key) DO UPDATE SET setting_value = $2, updated_at = NOW()
    `, ['ALERT_EMAIL_TO', ALERT_EMAIL_TO]);
    
    console.log('[AlertEmail] Settings saved: ALERT_EMAIL_TO =', ALERT_EMAIL_TO);
    
    res.json({ 
      message: 'Alert email settings saved',
      ALERT_EMAIL_TO 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= PAGES =============

// Scans page
app.get('/scans', requireAuth, (req, res) => {
  res.render('scans-new', { user: req.user });
});

// Alerts page
app.get('/alerts', requireAuth, (req, res) => {
  res.render('alerts-new', { user: req.user });
});

// Settings page
app.get('/settings', requireAuth, (req, res) => {
  if (!req.user?.is_admin) return res.redirect('/');
  res.render('settings-new', { user: req.user });
});

// Server detail page
app.get('/servers/:id', requireAuth, (req, res) => {
  res.render('server-detail-new', { user: req.user, serverId: req.params.id });
});

// ============= ERROR HANDLING =============
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============= START SERVER =============
async function start() {
  try {
    await initDb();
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`\n✅ ClamOrchestra läuft auf http://localhost:${PORT}`);
      console.log(`📝 Login: admin / admin\n`);
    });
  } catch (error) {
    console.error('❌ Fehler beim Starten:', error.message);
    process.exit(1);
  }
}

start();

export default app;
