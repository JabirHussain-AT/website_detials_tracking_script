import puppeteer from 'puppeteer';
import OpenAI from 'openai';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import chalk from 'chalk';
import dotenv from 'dotenv'
dotenv.config()

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class ScreenshotAnalyzer {
    constructor(options = {}) {
        this.options = {
            outputDir: path.join(process.cwd(), 'screenshot-analysis'),
            openaiApiKey: process.env.OPENAI_API_KEY || '',
            verbose: true,
            devices: {
                mobile: { width: 375, height: 667 },
                tablet: { width: 768, height: 1024 },
                desktop: { width: 1440, height: 900 }
            },
            ...options
        };

        if (!this.options.openaiApiKey) {
            throw new Error('OpenAI API key is required');
        }

        this.openai = new OpenAI({
            apiKey: this.options.openaiApiKey
        });

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

        console.log(logTypes[type](`[ScreenshotAnalyzer] ${message}`));
    }

    async captureScreenshots(url) {
        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-gpu']
        });

        try {
            const screenshots = {};
            for (const [device, dimensions] of Object.entries(this.options.devices)) {
                this._log(`Capturing ${device} screenshot for ${url}`);
                
                const page = await browser.newPage();
                await page.setViewport(dimensions);
                await page.goto(url, { waitUntil: 'networkidle0' });
                
                // Wait for any lazy-loaded content
                await page.evaluate(() => new Promise(resolve => {
                    setTimeout(resolve, 2000);
                }));

                const screenshotPath = path.join(
                    this.options.outputDir,
                    `${this._sanitizeFilename(url)}_${device}.png`
                );
                
                await page.screenshot({
                    path: screenshotPath,
                    fullPage: true
                });

                screenshots[device] = {
                    path: screenshotPath,
                    dimensions
                };

                await page.close();
            }

            return screenshots;
        } finally {
            await browser.close();
        }
    }

    async analyzeScreenshot(screenshotPath, device) {
        try {
            const image = await fs.promises.readFile(screenshotPath);
            const base64Image = image.toString('base64');

            this._log(`Analyzing ${device} screenshot with OpenAI`);

            const response = await this.openai.chat.completions.create({
                model: "gpt-4o",
                messages: [
                    {
                        role: "user",
                        content: [
                            {
                                type: "text",
                                text: `Analyze this ${device} screenshot and provide specific UI/UX improvement suggestions. Focus on:
                                1. Layout and spacing
                                2. Visual hierarchy
                                3. Mobile responsiveness
                                4. Navigation and user flow
                                5. Color contrast and accessibility
                                6. Content readability
                                Respond with actionable recommendations only. Avoid prefacing or additional context.`
                            },
                            {
                                type: "image_url",  // Changed from 'image' to 'image_url'
                                image_url: {
                                    url: `data:image/png;base64,${base64Image}`
                                }
                            }
                        ]
                    }
                ],
                max_tokens: 1000
            });

            return response.choices[0].message.content;
        } catch (error) {
            this._log(`Failed to analyze screenshot: ${error.message}`, 'error');
            throw error;
        }
    }

    async generateReport(url) {
        try {
            this._log(`Starting screenshot analysis for ${url}`);

            // Capture screenshots for all devices
            const screenshots = await this.captureScreenshots(url);

            // Analyze each screenshot
            const analyses = {};
            for (const [device, screenshot] of Object.entries(screenshots)) {
                analyses[device] = await this.analyzeScreenshot(screenshot.path, device);
            }

            // Generate report
            const report = {
                url,
                timestamp: new Date().toISOString(),
                screenshots,
                analyses
            };

            // Save report
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${this._sanitizeFilename(url)}_${timestamp}_screenshot_analysis.json`;
            const reportPath = path.join(this.options.outputDir, filename);

            fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
            this._log(`Analysis completed. Report saved to ${reportPath}`, 'success');

            // Print summary
            console.log('\nScreenshot Analysis Summary:');
            console.log('--------------------------');
            console.log(`URL: ${url}`);
            for (const [device, analysis] of Object.entries(analyses)) {
                console.log(`\n${device.toUpperCase()} Analysis:`);
                console.log(analysis);
            }

            return report;
        } catch (error) {
            this._log(`Analysis failed: ${error.message}`, 'error');
            throw error;
        }
    }

    _sanitizeFilename(url) {
        return url.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    }
}

// Example usage
const runAnalysis = async ( urlToTest ) => {
    try {
        const analyzer = new ScreenshotAnalyzer({
            verbose: true,
            outputDir: './screenshot-analysis'
        });

        const url = process.argv[2] || urlToTest || 'https://quantmutual.com/';
        console.log(`Starting screenshot analysis for: ${url}`);
        await analyzer.generateReport(url);
    } catch (error) {
        console.error('Analysis failed:', error);
        process.exit(1);
    }
};

// Run if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    runAnalysis('https://quantmutual.com/');
}

export default ScreenshotAnalyzer;