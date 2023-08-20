import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import express from 'express';
import { rateLimit } from 'express-rate-limit'
import https from 'https';
import { MiddlewareStack } from 'middleware-stack';
import process from 'process';
import winston from 'winston';

//import { RateLimit } from './errors.js';

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
		await this.configureMiddlewares(config.express);
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

		return;

		/*
		this.express.use((req, res, next) => {
			const iter = this.#middleWares[Symbol.iterator]();

			const nextCallback = () => {
				const current = iter.next();
				if (current.done) {
					next();
				} else {
					const middleWare = current.value;
					if (middleWare) {
						middleWare(req, res, nextCallback);
					} else {
						nextCallback();
					}
				}
			};
			nextCallback();
		});
		*/

		//this.express.use(this.#middleWares2.handle);

		/*this.express.use((req, res, next) => {
			if (req.method === 'POST') {
				// Default content-type
				req.headers['content-type'] = 'application/json';
			}
			next();
		});*/

		this.express.use(express.json({ limit: '10kb' }));

		this.express.use((error, req, res, next) => {
			// Handle bodyParser errors
			if (error instanceof SyntaxError) {
				BadBody.respond(res);
			}
			else next();
		});

		/*this.express.use((req, res, next) => {
			if (this.#config.allowedOrigins.length > 0 && req.get('origin') != undefined) {
				// check to see if its a valid domain
				const allowed = this.#config.allowedOrigins.indexOf(req.get('origin')) > -1 ||
					allowedRegexOrigins.findIndex((reg) => reg.test(req.get('origin'))) > -1;

				if (allowed) {
					res.header('Access-Control-Allow-Origin', req.get('origin'));
					res.header('Access-Control-Allow-Methods', 'GET');
				}
			}
			next()
		});*/

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

		if (config.rateLimit?.enable) {
			this.express.use(rateLimit({
				windowMs: config.rateLimit.windowMs,
				max: config.rateLimit.max,
				headers: false,
				handler: (req, res) => {
					RateLimit.respond(res);
				}
			}))
		}
	}

	configureMiddlewares(config = {}) {


		this.#middleWares.commit();
	}

	async configureHTTPS(config = {}) {
		console.log(config);
		const httpsPort = config.port;
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

	async #loadConfig(force = false) {
		try {
			const content = await readFile(this.#configPath);
			const config = JSON.parse(content);

			if (force || await this.validateConfig(config)) {
				await this.#setConfig(config);
			}

		} catch (e) {
			console.error('Error while loading config: ', e)
		}
	}

	async validateConfig(config) {
		if (!await this.#validateHTTPSConfig(config.https)) {
			return false;
		}
		return true;
	}

	async #validateHTTPSConfig(config) {
		try {
			const key = await readFile(config.keyFile);
			const cert = await readFile(config.certFile);

			const cryptoCrt = new X509Certificate(cert);
			const cryptoKey = createPrivateKey(key);

			if (!cryptoCrt.checkPrivateKey(cryptoKey)) {
				console.error('Unable to validate cert / key pair');
				return false;
			}


			return true;
		} catch (error) {
			console.error('Unable to validate https config ', error);
		}
		return false;
	}

	#signalHUP() {
		winston.info('HUP signal received, reloading config');
		this.#loadConfig();
	}
}
