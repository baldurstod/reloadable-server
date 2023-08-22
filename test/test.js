import { readFile } from 'node:fs/promises';

import { ReloadableServer } from '../src/reloadableserver.js';

class MyServer extends ReloadableServer {
	constructor() {
		super('config.example.json');
		this.#initExpressEndPoints();
	}

	#initExpressEndPoints() {
		this.express.post('/testget', (req, res) => this.#testGet(req, res));
		this.express.post('/testpost', (req, res) => this.#testPost(req, res));
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
}

const ms = new MyServer();
