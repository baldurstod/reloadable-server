import { X509Certificate, createPrivateKey, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import MongoStore from 'connect-mongo';
import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit'
import session from 'express-session';
import helmet from 'helmet';
import https from 'https';
import { MiddlewareStack } from 'middleware-stack';
import process from 'process';
import fileStore from 'session-file-store';
import winston from 'winston';

import { RateLimit, InternalError, BadBody } from './errors.js';

const COMBINED_LOG = 'combined.log'
const ERROR_LOG = 'error.log'
const EXCEPTION_LOG = 'exception.log'
const REJECTION_LOG = 'rejection.log'

const UUID_V4_PATTERN = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i

export class ReloadableServer {
	#configPath;
	#config;
	#errorConfig;
	#winstonLogger;
	#httpsServer;
	#middleWaresBefore = new MiddlewareStack();
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
		this.#errorConfig = config.express.handleErrors;
		await this.configureWinston(config.winston);

		// Log this message after winston config to avoid the write logs with no transports message
		winston.info('ReloadableServer initializing config');

		await this.configureExpress(config.express);
		await this.#configureMiddlewares(config.express?.middlewares);
		await this.#configureHTTPS(config.https);
		await this.configureApplication(config.application);
	}

	#initWinston() {
		this.#winstonLogger = winston.createLogger();
		winston.add(this.#winstonLogger);
	}

	#initExpress() {
		this.express = express();
		this.express.disable('x-powered-by');
		this.express.use(this.#middleWaresBefore.handle);
		this.express.use(this.#middleWares.handle);

		this.express.use((err, req, res, next) => this.#handleExpressError(err, req, res, next));
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

	configureWinston(winstonConfig = {}) {
		winston.level = winstonConfig.level ?? 'debug';
		this.#winstonLogger.exitOnError = false;

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
				new winston.transports.File({ filename: winstonConfig.errorLog ?? ERROR_LOG, level: 'error' }),
				new winston.transports.File({ filename: winstonConfig.combinedLog ?? COMBINED_LOG }),
			],
			exceptionHandlers: [
				new winston.transports.File({ filename: winstonConfig.exceptionLog ?? EXCEPTION_LOG }),
			],
			rejectionHandlers: [
				new winston.transports.File({ filename: winstonConfig.rejectionLog ?? REJECTION_LOG }),
			],
		});
	}

	configureExpress(expressConfig = {}) {
		this.express.set('trust proxy', expressConfig.trustProxy);
	}

	#configureMiddlewares(middlewaresConfig = {}) {
		const middleWares = [];

		middleWares.push(this.#configureRequestId(middlewaresConfig.requestId));
		middleWares.push(this.#configureSession(middlewaresConfig.session));
		middleWares.push(this.#configureRateLimit(middlewaresConfig.rateLimit));
		middleWares.push(this.#configureJSON(middlewaresConfig.json));
		middleWares.push(this.#configureCORS(middlewaresConfig.cors));
		middleWares.push(this.#configureHelmet(middlewaresConfig.helmet));
		middleWares.push(this.#configureStatic(middlewaresConfig.static));

		this.#middleWares.setMiddleWares(middleWares.flat());
	}

	#configureRequestId(requestIdConfig) {
		if (!requestIdConfig) {
			return;
		}

		if (requestIdConfig.enable ?? true) {
			const headerName = requestIdConfig.headerName ?? 'X-Request-Id';
			const setHeader = requestIdConfig.setHeader ?? true;

			return function (request, response, next) {
				const clientRequestId = request.get(headerName);

				const requestId = clientRequestId && UUID_V4_PATTERN.test(clientRequestId) ? clientRequestId : randomUUID();

				if (setHeader) {
					response.set(headerName, requestId);
				}

				request.requestId = requestId;

				next();
			};
		}
	}

	#configureSession(sessionConfig) {
		if (!sessionConfig) {
			return;
		}
		if (sessionConfig.enable ?? true) {
			let store;
			const storeType = sessionConfig.store.type;
			const storeOptions = sessionConfig.store.options;
			if (storeType == 'filestore') {
				store = new (fileStore(session))(storeOptions);
			} else if (storeType == 'mongo') {
				store = MongoStore.create(storeOptions);
			} else {
				throw `Unknown store ${storeType}`;
			}
			return session({
				store: store,
				cookie: sessionConfig.cookie,
				name: sessionConfig.name,
				resave: sessionConfig.resave,
				rolling: sessionConfig.rolling,
				secret: sessionConfig.sessionSecret,
				saveUninitialized: sessionConfig.saveUninitialized,
			});
		}
	}

	#configureRateLimit(rateLimitConfig) {
		if (!rateLimitConfig) {
			return;
		}
		if (rateLimitConfig.enable ?? true) {
			return rateLimit({
				windowMs: rateLimitConfig.options?.windowMs,
				max: rateLimitConfig.options?.max,
				standardHeaders: rateLimitConfig.options?.standardHeaders,
				legacyHeaders: rateLimitConfig.options?.legacyHeaders,
				handler: (req, res) => {
					RateLimit.respond(res);
				}
			})
		}
	}

	#configureJSON(jsonConfig) {
		if (!jsonConfig) {
			return;
		}
		if (jsonConfig.enable ?? true) {
			return express.json(jsonConfig.options);
		}
	}

	#configureCORS(corsConfig) {
		if (!corsConfig) {
			return;
		}
		if (corsConfig.enable ?? true) {
			return cors(corsConfig.options);
		}
	}

	#configureStatic(staticConfig) {
		if (!staticConfig) {
			return;
		}
		const staticMids = []
		if ((staticConfig.enable ?? true) && staticConfig.directories) {
			for (let dir of staticConfig.directories) {
				staticMids.push(express.static(dir.root, dir.options));
			}
		}
		return staticMids;
	}

	#configureHelmet(helmetConfig) {
		if (!helmetConfig) {
			return;
		}
		if (helmetConfig.enable ?? true) {
			return helmet(helmetConfig.options);
		}
	}

	#handleExpressError(err, req, res, next) {
		if (!this.#errorConfig) {
			next();
			return;
		}
		if (this.#errorConfig.enable ?? true) {
			const o = this.#errorConfig.options;

			winston.error(err);
			if (err instanceof SyntaxError) {
				if (o?.handleSyntaxError) {
					BadBody.respond(res);
					return;
				}
			} else {
				if (o?.handleAnyError) {
					InternalError.respond(res);
					return;
				}
			}
			next();
		}
	}

	async #configureHTTPS(httpsConfig = {}) {
		const httpsPort = parseInt(httpsConfig.port);
		if (!httpsPort) {
			throw 'https config is missing port';
		}

		const key = await readFile(httpsConfig.keyFile);
		const cert = await readFile(httpsConfig.certFile);

		this.#listen(httpsPort, key, cert);
	}

	async configureApplication(applicationConfig = {}) {
		// Override this function if you need your application config reloaded
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

		valid &&= await this.#validateHTTPSConfig(config.https);
		valid &&= await this.validateApplicationConfig(config.application);

		return valid;
	}

	async #validateHTTPSConfig(httpsConfig) {
		try {
			let valid = true;

			valid &&= this.#validateHTTPSPort(httpsConfig.port);
			valid &&= await this.#validateHTTPSCertificate(httpsConfig.keyFile, httpsConfig.certFile);

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

	async validateApplicationConfig(applicationConfig) {
		// Override this function if you need your application config validated
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

	get middleWaresBefore() {
		return this.#middleWaresBefore;
	}
}
