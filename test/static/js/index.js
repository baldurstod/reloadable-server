async function testBadRequest() {
	const response = await fetch('/test', {
		method: 'POST',
		headers : {
			'Content-Type': 'application/json',
		},
		body: {
			test: 1
		}
	});
}


testBadRequest();


async function testBadRequestId() {
	const response = await fetch('/testrequestid', {
		method: 'GET',
		headers : {
			'Content-Type': 'application/json',
			'X-Request-Id': 'my request id',
		},
	});
}
testBadRequestId()

async function testRequestId() {
	const response = await fetch('/testrequestid', {
		method: 'GET',
		headers : {
			'Content-Type': 'application/json',
			'X-Request-Id': crypto.randomUUID(),
		},
	});
}
testRequestId()
