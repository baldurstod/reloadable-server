import { readFile } from 'node:fs/promises';

import { ReloadableServer } from '../src/reloadableserver.js';

class MyServer extends ReloadableServer {
	constructor() {
		super('config.example.json');
		this.#initExpressEndPoints();
	}

	#initExpressEndPoints() {
		this.express.get('/', (req, res) => this.#get(req, res));
	}

	async #get(req, res) {
		try {
			res.json({success: true, result: {}});
		} catch(e) {
			winston.error('Error in get : ' + e, {url: req.url, params: req.params});
		}
	}
}

const ms = new MyServer();
