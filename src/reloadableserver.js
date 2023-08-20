import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit'
import https from 'https';
import { MiddlewareStack } from 'middleware-stack';
import process from 'process';
import winston from 'winston';

import { RateLimit, InternalError } from './errors.js';

const COMBINED_LOG = 'combined.log'
const ERROR_LOG = 'error.log'
const EXCEPTION_LOG = 'exception.log'

export class ReloadableServer {
	#configPath;
	#config;
	#winstonLogger;
	#httpsServer;
	#middleWares = new MiddlewareStack();
	constructor(configPath) {
		this.#configPath = configPath;
		this.#initWinston();
		this.#initExpress();
		this.#initHttps();
		this.#initSignals();
		this.#loadConfig();
	}

	async #setConfig(config = {}) {
		this.#config = config;
		await this.configureWinston(config.winston);

		// Log this message after winston config to avoid the write logs with no transports message
		winston.info('ReloadableServer initializing config');

		await this.configureExpress(config.express);
		await this.configureMiddlewares(config.express?.middlewares);
		await this.configureHTTPS(config.https);
	}

	#initWinston() {
		this.#winstonLogger = winston.createLogger();
		winston.add(this.#winstonLogger);
	}

	#initExpress() {
		this.express = express();
		this.express.disable('x-powered-by');
		this.express.use(this.#middleWares.handle);
		this.express.use((err, req, res, next) => {
			winston.error(err.stack);
			//res.status(500).send('Internal server error');
			InternalError.respond(res);
		});

		return;

		//this.express.use(this.#middleWares2.handle);

		/*this.express.use((req, res, next) => {
			if (req.method === 'POST') {
				// Default content-type
				req.headers['content-type'] = 'application/json';
			}
			next();
		});*/

		this.express.use((error, req, res, next) => {
			// Handle bodyParser errors
			if (error instanceof SyntaxError) {
				BadBody.respond(res);
			}
			else next();
		});
	}

	#initHttps() {
		this.#httpsServer = https.Server({}, this.express);
	}

	async #listen(port, key, cert) {
		await this.#close();
		winston.info(`Listening on port ${port}`);
		this.#httpsServer.setSecureContext({ key: key, cert: cert });
		this.#httpsServer.listen(port);
	}

	async #close() {
		let closePromiseResolve;
		const closePromise = new Promise(resolve => {
			closePromiseResolve = resolve;
		});
		this.#httpsServer.close(() => {
			closePromiseResolve(true);
		});

		await closePromise;
	}

	configureWinston(config = {}) {
		console.log(config);
		winston.level = config.level ?? 'debug';

		const format = winston.format;
		const loggerFormat = format.combine(
			format.errors({ stack: true }),
			format.timestamp(),
			format.json()
		)

		this.#winstonLogger.configure({
			level: winston.level,
			format: loggerFormat,
			transports: [
				new winston.transports.File({ filename: config.errorLog ?? ERROR_LOG, level: 'error' }),
				new winston.transports.File({ filename: config.combinedLog ?? COMBINED_LOG }),
			],
			exceptionHandlers: [
				new winston.transports.File({ filename: config.exceptionLog ?? EXCEPTION_LOG })
			]
		})
	}

	configureExpress(config = {}) {
		this.express.set('trust proxy', config.trustProxy);
	}

	configureMiddlewares(config = {}) {
		const middleWares = [];

		middleWares.push(this.#configureRateLimit(config.rateLimit));
		middleWares.push(this.#configureJSON(config.json));
		middleWares.push(this.#configureCORS(config.cors));

		this.#middleWares.setMiddleWares(middleWares);
	}

	#configureRateLimit(config = {}) {
		if (config.enable) {
			return rateLimit({
				windowMs: config.windowMs,
				max: config.max,
				standardHeaders: config.standardHeaders,
				handler: (req, res) => {
					RateLimit.respond(res);
				}
			})
		}
	}

	#configureJSON(config = {}) {
		if (config.enable) {
			return express.json({ limit: config.limit });
		}
	}

	#configureCORS(corsConfig = {}) {
		if (corsConfig.enable) {
			return cors({
				origin: corsConfig.origin,
				methods: corsConfig.methods,
				allowedHeaders: corsConfig.allowedHeaders,
				exposedHeaders: corsConfig.exposedHeaders,
				credentials: corsConfig.credentials,
				maxAge: corsConfig.maxAge,
				preflightContinue: corsConfig.preflightContinue,
			});
		}
	}

	async configureHTTPS(config = {}) {
		const httpsPort = parseInt(config.port);
		if (!httpsPort) {
			throw 'https config is missing port';
		}

		const key = await readFile(config.keyFile);
		const cert = await readFile(config.certFile);

		this.#listen(httpsPort, key, cert);
	}

	#initSignals() {
		process.on('SIGHUP', () => this.#signalHUP());

		if (process.platform == 'win32') {
			// On win SIGBREAK will be used to simulate SIGHUP
			process.on('SIGBREAK', () => this.#signalHUP());
		}
	}

	async #loadConfig() {
		try {
			const content = await readFile(this.#configPath);
			const config = JSON.parse(content);

			if (await this.validateConfig(config)) {
				await this.#setConfig(config);
				return true;
			} else {
				console.error('Config validation failed');
				return false;
			}

		} catch (e) {
			console.error('Error while loading config: ', e)
		}
		return false;
	}

	async validateConfig(config) {
		let valid = true;

		valid &&= this.#validateHTTPSConfig(config.https);

		return valid;
	}

	async #validateHTTPSConfig(config) {
		try {
			let valid = true;

			valid &&= this.#validateHTTPSPort(config.port);
			valid &&= this.#validateHTTPSCertificate(config.keyFile, config.certFile);

			return valid;
		} catch (error) {
			console.error('Unable to validate https config ', error);
			return false;
		}
	}

	#validateHTTPSPort(port) {
		const httpsPort = parseInt(port);

		if (Number.isNaN(httpsPort)) {
			console.error('HTTPS port is NaN');
			return false;
		}

		if (httpsPort < 1024) {
			console.error('HTTPS port is < 1024');
			return false;
		}

		if (httpsPort > 0xFFFF) {
			console.error('HTTPS port is > 0xFFFF');
			return false;
		}
		return true;
	}

	async #validateHTTPSCertificate(keyFile, certFile) {
		const key = await readFile(keyFile);
		const cert = await readFile(certFile);

		const cryptoCrt = new X509Certificate(cert);
		const cryptoKey = createPrivateKey(key);

		if (!cryptoCrt.checkPrivateKey(cryptoKey)) {
			console.error('Unable to validate cert / key pair');
			return false;
		}
		return true;
	}

	async #signalHUP() {
		winston.info('HUP signal received, reloading config');
		if (await this.#loadConfig()) {
			console.error('Config successfully reloaded');
		} else {
			console.error('An error occured while reloading config');
		}
	}
}
