import puppeteer from 'puppeteer';
import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv'
dotenv.config()

// Get the current file's directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class WebsiteAuditor {
    constructor(options = {}) {
        this.options = {
            outputDir: path.join(process.cwd(), 'audit-reports'),
            verbose: true,
            timeout: 30000,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            ...options
        };

        if (!fs.existsSync(this.options.outputDir)) {
            fs.mkdirSync(this.options.outputDir, { recursive: true });
        }
    }

    _log(message, type = 'info') {
        if (!this.options.verbose) return;

        const logTypes = {
            info: chalk.blue,
            error: chalk.red,
            warning: chalk.yellow,
            success: chalk.green
        };

        console.log(logTypes[type](`[WebsiteAuditor] ${message}`));
    }

    async analyzePerformance(url) {
        let chrome;
        try {
            this._log(`Running performance analysis for ${url}`);
            
            chrome = await chromeLauncher.launch({
                chromeFlags: [
                    '--headless=new',
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage'
                ]
            });

            const options = {
                logLevel: 'info',
                output: 'json',
                port: chrome.port,
                onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo']
            };

            const result = await lighthouse(url, options);
            if (!result || !result.lhr) {
                throw new Error('Lighthouse failed to generate results');
            }
            
            return this._processLighthouseResults(result.lhr);
        } catch (error) {
            this._log(`Performance analysis failed: ${error.message}`, 'error');
            return {
                performance: { score: 0, metrics: {} },
                accessibility: { score: 0, issues: [] },
                bestPractices: { score: 0 },
                seo: { score: 0 }
            };
        } finally {
            if (chrome) {
                await chrome.kill();
            }
        }
    }

    _processLighthouseResults(results) {
        return {
            performance: {
                score: results.categories.performance.score * 100,
                metrics: {
                    firstContentfulPaint: results.audits['first-contentful-paint'].numericValue,
                    largestContentfulPaint: results.audits['largest-contentful-paint'].numericValue,
                    speedIndex: results.audits['speed-index'].numericValue,
                    totalBlockingTime: results.audits['total-blocking-time'].numericValue,
                    cumulativeLayoutShift: results.audits['cumulative-layout-shift'].numericValue
                }
            },
            accessibility: {
                score: results.categories.accessibility.score * 100,
                issues: Object.values(results.audits)
                    .filter(audit => audit.scoreDisplayMode !== 'notApplicable' && audit.category === 'accessibility')
                    .map(audit => ({
                        title: audit.title,
                        description: audit.description,
                        score: audit.score
                    }))
            },
            bestPractices: {
                score: results.categories['best-practices'].score * 100
            },
            seo: {
                score: results.categories.seo.score * 100
            }
        };
    }

    async analyzeSecurity(url) {
        try {
            this._log(`Analyzing security for ${url}`);
            
            const response = await axios.get(url, {
                headers: { 'User-Agent': this.options.userAgent },
                validateStatus: () => true
            });

            const headers = response.headers;
            const securityHeaders = {
                'Strict-Transport-Security': headers['strict-transport-security'] || null,
                'Content-Security-Policy': headers['content-security-policy'] || null,
                'X-Frame-Options': headers['x-frame-options'] || null,
                'X-Content-Type-Options': headers['x-content-type-options'] || null,
                'Referrer-Policy': headers['referrer-policy'] || null,
                'Permissions-Policy': headers['permissions-policy'] || null,
                'X-XSS-Protection': headers['x-xss-protection'] || null
            };

            const securityScore = this._calculateSecurityScore(securityHeaders);

            return {
                headers: securityHeaders,
                score: securityScore,
                recommendations: this._generateSecurityRecommendations(securityHeaders)
            };
        } catch (error) {
            this._log(`Security analysis failed: ${error.message}`, 'error');
            return {
                headers: {},
                score: 0,
                recommendations: []
            };
        }
    }

    _calculateSecurityScore(headers) {
        const weights = {
            'Strict-Transport-Security': 20,
            'Content-Security-Policy': 25,
            'X-Frame-Options': 15,
            'X-Content-Type-Options': 15,
            'Referrer-Policy': 10,
            'Permissions-Policy': 10,
            'X-XSS-Protection': 5
        };

        let score = 0;
        for (const [header, value] of Object.entries(headers)) {
            if (value) score += weights[header];
        }

        return score;
    }

    _generateSecurityRecommendations(headers) {
        const recommendations = [];

        if (!headers['Strict-Transport-Security']) {
            recommendations.push({
                priority: 'High',
                message: 'Implement HSTS to enforce HTTPS connections'
            });
        }

        if (!headers['Content-Security-Policy']) {
            recommendations.push({
                priority: 'High',
                message: 'Implement Content Security Policy to prevent XSS attacks'
            });
        }

        return recommendations;
    }

    async analyzeAccessibility(url) {
        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-gpu']
        });

        try {
            const page = await browser.newPage();
            await page.goto(url, { waitUntil: 'networkidle0' });

            const accessibilityReport = await page.evaluate(() => {
                const report = {
                    images: { total: 0, withAlt: 0 },
                    headings: { total: 0, structure: [] },
                    landmarks: { total: 0, types: {} },
                    forms: { total: 0, withLabels: 0 },
                    ariaAttributes: { total: 0, elements: [] }
                };

                document.querySelectorAll('img').forEach(img => {
                    report.images.total++;
                    if (img.hasAttribute('alt')) report.images.withAlt++;
                });

                document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(heading => {
                    report.headings.total++;
                    report.headings.structure.push(heading.tagName);
                });

                document.querySelectorAll('main, nav, header, footer, aside, section, article').forEach(landmark => {
                    report.landmarks.total++;
                    report.landmarks.types[landmark.tagName.toLowerCase()] = 
                        (report.landmarks.types[landmark.tagName.toLowerCase()] || 0) + 1;
                });

                document.querySelectorAll('form').forEach(form => {
                    report.forms.total++;
                    const inputs = form.querySelectorAll('input, select, textarea');
                    const labelsCount = form.querySelectorAll('label').length;
                    if (labelsCount >= inputs.length) report.forms.withLabels++;
                });

                return report;
            });

            return accessibilityReport;
        } catch (error) {
            this._log(`Accessibility analysis failed: ${error.message}`, 'error');
            return {
                images: { total: 0, withAlt: 0 },
                headings: { total: 0, structure: [] },
                landmarks: { total: 0, types: {} },
                forms: { total: 0, withLabels: 0 },
                ariaAttributes: { total: 0, elements: [] }
            };
        } finally {
            await browser.close();
        }
    }

    async generateFullReport(url) {
        this._log(`Starting full website audit for ${url}`);

        try {
            // Run analyses sequentially to avoid resource conflicts
            const performance = await this.analyzePerformance(url);
            this._log('Performance analysis completed');

            const security = await this.analyzeSecurity(url);
            this._log('Security analysis completed');

            const accessibility = await this.analyzeAccessibility(url);
            this._log('Accessibility analysis completed');
            const stressTest = await this.analyzeButtonsAndFields(url);
            const report = {
                url,
                timestamp: new Date().toISOString(),
                performance,
                security,
                stressTest,
                accessibility,
                overallScore: this._calculateOverallScore(performance, security)
            };

            // Save report with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${this._sanitizeFilename(url)}_${timestamp}_audit_report.json`;
            const reportPath = path.join(this.options.outputDir, filename);
            
            fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
            this._log(`Audit completed successfully. Report saved to ${reportPath}`, 'success');
            
            // Print summary to console
            console.log('\nAudit Summary:');
            console.log('--------------');
            console.log(`URL: ${url}`);
            console.log(`Overall Score: ${report.overallScore}`);
            console.log(`Performance Score: ${report.performance.performance.score}`);
            console.log(`Security Score: ${report.security.score}`);
            console.log(`Accessibility Issues: ${report.accessibility.headings.total}`);
            
            return report;
        } catch (error) {
            this._log(`Audit failed: ${error.message}`, 'error');
            throw error;
        }
    }

    _calculateOverallScore(performance, security) {
        const weights = {
            performance: 0.4,
            security: 0.3,
            accessibility: 0.3
        };

        return Math.round(
            (performance.performance.score * weights.performance) +
            (security.score * weights.security)
        );
    }

    _sanitizeFilename(url) {
        return url.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    }

    async analyzeButtonsAndFields(url, concurrency = 1000) {
        const browser = await puppeteer.launch({ headless: true });
        const page = await browser.newPage();
    
        try {
            await page.setUserAgent(this.options?.userAgent || 'Mozilla/5.0');
            await page.goto(url, { waitUntil: 'networkidle0' });
    
            const buttons = await page.$$eval('button', (btns) =>
                btns.map((button, index) => ({
                    index,
                    text: button.innerText,
                    success: false,
                    error: null,
                }))
            );
    
            const inputFields = await page.$$eval('input', (inputs) =>
                inputs.map((input, index) => ({
                    index,
                    type: input.getAttribute('type') || 'text',
                    placeholder: input.getAttribute('placeholder') || 'No placeholder',
                    valueBefore: input.value,
                    valueAfter: null,
                    success: false,
                    error: null,
                }))
            );
    
            // Handle button clicks concurrently
            const buttonClickPromises = buttons.map(async (button, i) => {
                try {
                    await page.evaluate((index) => {
                        const btn = document.querySelectorAll('button')[index];
                        btn.click();
                    }, button.index);
                    buttons[i].success = true;
                } catch (error) {
                    buttons[i].error = error.message;
                }
            });
    
            // Split promises into chunks for concurrency
            const chunkedButtonPromises = chunkArray(buttonClickPromises, concurrency);
            for (const chunk of chunkedButtonPromises) {
                await Promise.all(chunk); // Execute each chunk concurrently
            }
    
            // Autofill and validate input fields
            const inputPromises = inputFields.map(async (input, i) => {
                try {
                    await page.evaluate((index, value) => {
                        const inputField = document.querySelectorAll('input')[index];
                        inputField.value = value;
                        inputField.dispatchEvent(new Event('input'));
                    }, input.index, `test value ${i}`); // Autofill with unique test values
    
                    inputFields[i].valueAfter = `test value ${i}`;
                    inputFields[i].success = true;
                } catch (error) {
                    inputFields[i].error = error.message;
                }
            });
    
            // Split promises into chunks for concurrency
            const chunkedInputPromises = chunkArray(inputPromises, concurrency);
            for (const chunk of chunkedInputPromises) {
                await Promise.all(chunk);
            }
    
            // Analyze CORS
            const cors = await page.evaluate(() => {
                const corsDetails = {};
                const methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
                methods.forEach((method) => {
                    corsDetails[method] = {
                        allowed: document.createElement('div') ? true : false,
                    };
                });
                return corsDetails;
            });
    
            return {
                buttons,
                inputFields,
                cors,
            };
        } catch (error) {
            console.error(`Button and field analysis failed: ${error.message}`);
            return { buttons: [], inputFields: [], cors: {} };
        } finally {
            await browser.close();
        }
    }
}
    // Utility function to split an array into chunks
    function chunkArray(array, size) {
        const results = [];
        for (let i = 0; i < array.length; i += size) {
            results.push(array.slice(i, i + size));
        }
        return results;
    }
    

// Simple CLI interface
const runAudit = async ( urlToTest ) => {
    try {
        const auditor = new WebsiteAuditor({
            verbose: true,
            outputDir: './website-audit-reports'
        });

        const url = urlToTest ?? 'https://quantmutual.com/'
        if (!url) {
            console.error('Please provide a URL to audit');
            console.log('Usage: node script.js <url>');
            process.exit(1);
        }

        console.log(`Starting audit for: ${url}`);
        await auditor.generateFullReport(url);
    } catch (error) {
        console.error('Audit failed:', error);
        process.exit(1);
    }
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    runAudit('https://quantmutual.com/');
}
