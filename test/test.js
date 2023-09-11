import { readFile } from 'node:fs/promises';

import { ReloadableServer } from '../src/reloadableserver.js';

class MyServer extends ReloadableServer {
	constructor() {
		super('example.config.json');
		this.#initExpressEndPoints();
	}

	#initExpressEndPoints() {
		this.express.get('/testget', (req, res) => this.#testGet(req, res));
		this.express.post('/testpost', (req, res) => this.#testPost(req, res));
		this.express.all('/testrequestid', (req, res) => this.#testRequestId(req, res));
	}

	async #testGet(req, res) {
		try {
			res.json({success: true, result: {}});
		} catch(e) {
			winston.error('Error in get : ' + e, {url: req.url, params: req.params});
		}
	}

	async #testPost(req, res) {
		try {
			console.log(req.body);
			res.json({success: true, result: {}});
		} catch(e) {
			winston.error('Error in get : ' + e, {url: req.url, params: req.params});
		}
	}

	async #testRequestId(req, res) {
		try {
			console.log(req.requestId);
			res.json({success: true, result: {}});
		} catch(e) {
			winston.error('Error in get : ' + e, {url: req.url, params: req.params});
		}
	}
}

const ms = new MyServer();
